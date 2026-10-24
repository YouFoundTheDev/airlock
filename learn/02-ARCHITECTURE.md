<!-- © https://github.com/YouFoundTheDev | 2026 -->
<!-- 02-ARCHITECTURE.md -->

# Architecture

## High level

```
                        YOUR APPLICATION
                               |
              declares provenance explicitly
                               |
                        Envelope
                               |
              +----------------+----------------+
              |                                 |
        engine.inspect()                 engine.compose()
        residue, phrasing, fence                 |
              |                          rendered prompt
        Outcome  ---- REFUSE? stop               |
              |                                 v
              |                            +---------+
              |                            |  model  |
              |                            +----+----+
              |                                 |
              |                          Reply (prose + proposals)
              |                                 |
              |                        engine.authorize()
              |                        grant, spill
              |                                 |
              +----------->  Outcome  <----------+
                          permit / refuse
```

Two inspection points, not one. `inspect()` runs before the model. `authorize()`
runs after. They share the decision algebra and nothing else.

## Module map

| Module | Owns | Decides? |
|---|---|---|
| `envelope.py` | The provenance-tagged prompt. Exposure derivation | n/a |
| `ruling.py` | `Weight`, `Ruling`, `Alert`, `Outcome` | n/a |
| `contract.py` | Which checks run, thresholds, `promote()`, `resolve()` | n/a |
| `engine.py` | Orchestration, wrapping, fail-closed handling | yes, from alerts |
| `capability.py` | `Impact`, `Requirement`, `Capability`, `Proposal`, `Reply` | n/a |
| `codec/surface.py` | Tag block, zero-width, bidi, lookalikes, NFKC | reads bytes, decides nothing |
| `codec/peel.py` | Transport decoding, whole-body and inline | reads bytes, decides nothing |
| `codec/spectrum.py` | The bounded closure over reversible readings | shared by three checks |
| `checks/residue.py` | Emits alerts for every transform required | no |
| `checks/phrasing.py` | Template tokens, instruction-shaped prose | **yes, and it is labelled** |
| `checks/fence.py` | Nonce presence in external content | no |
| `checks/grant.py` | Exposure, requirements, denied impacts, schema | no |
| `checks/spill.py` | Secret closure, host control | no |
| `journal.py` | JSONL records carrying no attacker content | n/a |
| `agents/scripted.py` | The deliberately gullible model | n/a |
| `server/` | Arena, proxy, levels, sessions, harvest | n/a |

## The data model

### Provenance

`Provenance` has three values: `INSTRUCTION`, `REQUEST`, `CONTENT`.

- `INSTRUCTION` is text the operator wrote. It is never inspected by the
  residue or phrasing checks, because the operator is inside the trust boundary.
- `REQUEST` is text the human at the keyboard wrote. It is inspected for
  residue but not for phrasing, because "ignore that" from a user is a normal
  sentence about their own conversation.
- `CONTENT` is everything else, and it must carry a `Source`. It is the only
  provenance that can trigger the phrasing rule, and the only one that exposes
  the envelope.

A `Segment` enforces this at construction: a `CONTENT` segment without a source
raises, and an `INSTRUCTION` or `REQUEST` segment with one also raises. The type
cannot represent an unlabelled document.

### Envelope

`Envelope` is frozen, and every builder method returns a new instance, so an
envelope cannot be mutated out from under an outcome that already described it.

```python
@dataclass(frozen = True, slots = True)
class Envelope:
    segments: tuple[Segment, ...] = ()
    nonce: str = field(default_factory = fresh_nonce)

    @property
    def exposed(self) -> tuple[Source, ...]:
        return tuple(
            segment.source for segment in self.segments
            if segment.provenance is Provenance.CONTENT
            and segment.source is not None
        )
```

Exposure is derived, never stored. There is no `taint()` setter and no
`clear_taint()` method, because both would let the flag disagree with the
segments.

### Alerts name themselves

```python
Alert(check = "fence", rule = "fence-forged",
      weight = Weight.CRITICAL, hard = True,
      segment = 2, evidence = "fence nonce present in content")
```

Every alert carries its check and rule so a consumer can render
`refused by fence/fence-forged`. This is not cosmetic. The arena's entire
teaching mechanism is that the player sees which rule stopped them, so ruling
legibility is a hard requirement rather than a nicety.

## The decision algebra

Two pure functions over alerts, both in `contract.py`.

```
promote(alerts, contract):
  if contract.strict:
    every alert whose rule is in STRICT_RULES becomes hard
  return alerts

resolve(alerts, contract):
  if any alert is hard: REFUSE
  scored = [a.weight for a in alerts if not a.hard and a.weight > INFO]
  if scored and max(scored) >= contract.threshold: REFUSE
  return PERMIT
```

Four rules hold this together:

**Hard alerts are not thresholded.** No contract setting disables one.
`threshold` only ever moves the bar for soft alerts.

**INFO never refuses.** `resolve()` filters `weight > Weight.INFO` out of the
scored comparison. This exists so `check-muted` notices can ride along in every
outcome without ever affecting it.

**Promotion is a pure function over alerts, not a check.** An earlier design had
the fence check re-emit phrasing alerts as hard. That would require one check to
receive another check's output, which breaks the uniform `run(envelope, contract)`
shape that lets the engine wrap all checks identically.

**The two kinds are never blended.** A contract can raise or lower `threshold`
all it likes; it cannot turn a guess into a guarantee, because the field that
decides is `hard`, not the number.

## The check protocol

```python
class InboundCheck(Protocol):
    name: str

    def run(
        self,
        envelope: Envelope,
        contract: Contract,
    ) -> list[Alert]:
        ...
```

A check reports. It does not refuse, log, or call another check. That is what
makes the fail-closed wrapper possible: the engine can wrap every check the same
way because none of them can do anything except return a list.

`grant` and `spill` are outbound and do not fit this protocol, because they read
a `Reply` rather than an `Envelope`. The engine calls them from `authorize()`
with their own signatures.

## Failure modes fail closed

Every inbound check call is wrapped:

```python
def _run(self, name: str, envelope: Envelope) -> list[Alert]:
    if not self._enabled(name):
        return [self._muted(name)]

    try:
        return self.inbound[name].run(envelope, self.contract)
    except Exception as error:
        return [self._fault(name, error)]
```

An exception becomes `Alert(rule="check-fault", weight=CRITICAL, hard=True)`,
which forces `REFUSE`. A firewall that fails open on an unhandled exception is
worse than no firewall, because it reports success while doing nothing.

**A muted check is recorded, not silent.** `check-muted` at INFO weight enters
the outcome, so a consumer can always distinguish "this check ran and found
nothing" from "this check never ran". The arena uses exactly this to tell a
player that level 2 was winnable because a check was off, not because the attack
was clever.

## The checks

### residue

Runs `flatten()` then `peel()` over every segment the operator did not author,
forwarding every alert each stage produced. It never decides anything: an
unedited text with a tag-block payload produces a `HIGH` alert, and whether that
refuses is the contract's business.

### phrasing

The scored check. Two rules, both scoped to `Provenance.CONTENT`:

- `template-token` at `HIGH`
- `instructional-prose` at `MODERATE`

It reads a bounded spectrum of readings, not the raw string, because base64 and
separator tricks are cheap. It is the only check that can be wrong about a
payload, and the only one whose alerts are promoted by `strict`.

### fence

Compares the envelope's nonce against every reading of every external segment.
`alnum_only` on both sides means a nonce interrupted by separators still counts.
A hit is `CRITICAL` and hard, because attacker text has no legitimate route to a
value drawn from the CSPRNG after the text arrived.

### grant

For each proposal in a reply:

1. Look it up. An undeclared capability is refused.
2. Refuse any impact the contract denies.
3. Refuse missing required arguments, undeclared arguments, and schema failures.
4. Refuse `UNTAINTED` capabilities when the envelope is exposed.
5. Refuse `CONFIRMED` capabilities that were not confirmed.
6. Refuse `ALLOWLISTED` capabilities whose allowlisted argument is absent or
   off-list.

Every one of those is hard. There is no threshold at which an unauthorized
action becomes acceptable.

### spill

Two mechanisms over the outbound surfaces (prose plus every proposal argument
flattened to text):

- Secret matching over the closure of readings, so a secret survives no encoding
  the closure can undo.
- Host allowlisting by exact match or `.suffix` match, applied to every URL the
  regex finds, including markdown images and protocol-relative forms.

A surface larger than 64 KiB is refused before matching, because scanning it
would be both slow and a bypass opportunity.

## Storage

Almost nothing, deliberately.

| What | Where | Why |
|---|---|---|
| Sessions | in memory, LRU + TTL | The arena is a demo, not an account system |
| Journal records | JSONL at `AIRLOCK_AUDIT_PATH`, disabled by default | No path means no records, which is the right default |
| Bypass payloads | JSONL at `AIRLOCK_BYPASS_PATH` | So `just harvest` has something to read |
| Corpus | YAML in the repo | Reviewed by hand, never written by the application |

The core library performs **no I/O at all**. No network, no filesystem, no clock
reads beyond elapsed-time measurement. That is what makes it testable and what
makes the arena safe to expose.

### The journal record carries no attacker content

```json
{"contract_id":"level-6","ruling":"refuse","took_ms":0.027,
 "segments":[{"provenance":"content","source":"ticket:ab15089d7d9114ef"}],
 "alerts":[{"check":"phrasing","rule":"instructional-prose",
            "weight":"MODERATE","hard":true,"segment":2,
            "evidence_digest":"3081bc7f2caf4077"}]}
```

Both `evidence` and the source `ref` are digested. Evidence is derived from
segment text, and in proxy mode the source ref comes straight out of the request
body, so both are attacker-influenced. A log the operator considers safe to keep
must not become a place attacker content is stored.

## Deployment

```
                    Cloudflare tunnel (optional overlay)
                               |
                               v
              +----------------------------------+
              |  nginx  (serves the built UI,    |
              |          proxies /api)           |
              |  127.0.0.1:33572                 |
              +----------------+-----------------+
                               |  internal network only
              +----------------v-----------------+
              |  arena  (FastAPI, uvicorn)       |
              |  read_only: true                 |
              |  cap_drop: ALL                   |
              |  no-new-privileges               |
              |  tmpfs /tmp                      |
              |  volume /var/lib/airlock         |
              |  cpus 1.0, memory 512M           |
              +----------------------------------+
```

The API container is never published to the host. Only nginx binds a port, and it
binds to `127.0.0.1`.

**Ports are configurable high numbers, never defaults.** UI `33572`, dev UI
`61878`, proxy `39441`. Binding a well-known port is how you collide with
whatever else the operator is already running.

**The container image bakes the virtualenv and the entrypoint calls `uvicorn`
directly.** An earlier version ran `uv run uvicorn` at container start, which
re-resolves the environment on every boot and, more importantly, needs a
writable cache. Under `read_only: true` it restart-looped on `Could not create
temporary file`. No test could have caught that, because the suite never starts
a container.

**Dev and prod are namespace-isolated by construction.** Project names and
container names are structural literals, one set per compose file, never
variables. Each compose recipe passes its own env file explicitly. There is
nothing to switch between environments and therefore nothing to forget.

## The proxy is the weak mode

`server/chat.py` exposes `/v1/chat/completions` and infers provenance from
message roles:

| Role | Provenance | Why |
|---|---|---|
| `system`, `developer` | `INSTRUCTION` | Operator text, inside the boundary |
| `user`, `assistant` | `REQUEST` | Human text; a prior assistant turn is re-read as semi-trusted |
| `tool`, `function` | `CONTENT` | Tool output is external, and gets a source |
| anything else | `CONTENT` | Fails closed rather than being promoted |

Two consequences, documented everywhere they are used:

- Retrieved content pasted into a `user` message is seen as `REQUEST`, so
  phrasing does not fire on it. The hard checks still hold, because they do not
  depend on the role.
- Mapping a prior assistant turn to `CONTENT` would expose every conversation
  after the first turn and make authorization useless in proxy mode, so it does
  not.

The startup log, the README, and a test all assert that this warning is printed.
A limitation that is not announced is a lie by omission.

## Threat model

**Inside the boundary:** the operator's instructions, the contract, the
capability registry, the engine code, the process.

**Outside the boundary:** any text that reaches a `CONTENT` segment, the model
itself, anything the model claims to have read.

**Consequences:** an attacker who controls a `CONTENT` segment can make the model
say or propose anything. They cannot make the engine grant a capability the
contract denies, make a registered secret leave in a form the closure can undo,
or forge a nonce drawn after their text arrived.

That is the whole claim. Everything else in this document is in service of it.
