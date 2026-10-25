// ===================
// © https://github.com/YouFoundTheDev | 2026
// index.tsx
// ===================

import { useMemo, useState } from 'react'

import { useAttempt, useCodepoints, useLevels, useSession } from '@/api/hooks'
import type { Alert, AttemptResponse, Level } from '@/api/types'
import {
  ARENA,
  CENSUS_MARKS,
  CHECK_ORDER,
  COPY,
  NUMERAL_PAD,
  RULE_CHECK_MUTED,
  RULING,
  SESSION_ID_HEAD,
} from '@/config'
import { ApiError } from '@/core/api/errors'
import {
  type CodepointSets,
  census,
  FALLBACK_CODEPOINTS,
  hiddenTotal,
  segments,
} from '@/core/lib'

import styles from './arena.module.scss'

type NodeState = 'off' | 'on' | 'pass' | 'hit' | 'stop' | 'held'

const NODE_LABEL: Record<NodeState, string> = {
  off: COPY.SIGNAL_OFF,
  on: COPY.SIGNAL_ON,
  pass: COPY.SIGNAL_PASS,
  hit: COPY.SIGNAL_HIT,
  stop: COPY.SIGNAL_STOP,
  held: COPY.UNREACHED,
}

function numeral(value: number): string {
  return String(value).padStart(NUMERAL_PAD, '0')
}

function attemptMessage(error: Error | null): string {
  const status = error instanceof ApiError ? error.statusCode : 0
  return COPY.ERRORS[status as keyof typeof COPY.ERRORS] ?? COPY.ERRORS.DEFAULT
}

function firedAlerts(result: AttemptResponse): Alert[] {
  return result.alerts.filter((alert) => alert.rule !== RULE_CHECK_MUTED)
}

function refused(result: AttemptResponse): boolean {
  return (
    result.inbound_ruling === RULING.REFUSE ||
    result.outbound_ruling === RULING.REFUSE
  )
}

function LevelButton({
  level,
  selected,
  onSelect,
}: {
  level: Level
  selected: boolean
  onSelect: (value: number) => void
}): React.ReactElement {
  return (
    <button
      type="button"
      className={styles.level}
      data-selected={selected}
      aria-pressed={selected}
      onClick={() => onSelect(level.number)}
    >
      <span className={styles.levelNum}>{numeral(level.number)}</span>
      <span className={styles.levelName}>{level.title}</span>
      <span className={styles.pips} aria-hidden="true">
        {CHECK_ORDER.map((check) => (
          <span
            key={check}
            className={styles.pip}
            data-on={level.active_checks.includes(check)}
          />
        ))}
      </span>
    </button>
  )
}

function SignalPath({
  level,
  result,
}: {
  level: Level
  result?: AttemptResponse
}): React.ReactElement {
  const fired = new Set<string>(
    (result?.alerts ?? [])
      .filter((alert) => alert.rule !== RULE_CHECK_MUTED)
      .map((alert) => alert.check)
  )
  const muted = new Set<string>(
    (result?.alerts ?? [])
      .filter((alert) => alert.rule === RULE_CHECK_MUTED)
      .map((alert) => alert.check)
  )
  const stopped = result !== undefined && refused(result)
  const firstHit = CHECK_ORDER.find((check) => fired.has(check)) ?? null
  const stopIndex =
    stopped && firstHit !== null ? CHECK_ORDER.indexOf(firstHit) : -1

  const stateOf = (check: string, index: number): NodeState => {
    const active = level.active_checks.includes(check)
    if (!active || muted.has(check)) {
      return 'off'
    }
    if (stopIndex >= 0 && index > stopIndex) {
      return 'held'
    }
    if (fired.has(check)) {
      return index === stopIndex ? 'stop' : 'hit'
    }
    return result === undefined ? 'on' : 'pass'
  }

  const onCount = level.active_checks.length

  return (
    <section className={styles.signal} data-refused={stopped}>
      <div className={styles.sectionHead}>
        <h2 className={styles.heading}>{COPY.SIGNAL_HEADING}</h2>
        <span className={styles.meta}>
          {onCount} of {CHECK_ORDER.length} {COPY.SIGNAL_ON}
        </span>
      </div>

      <ol className={styles.path}>
        {CHECK_ORDER.map((check, index) => {
          const state = stateOf(check, index)
          return (
            <li key={check} className={styles.node} data-state={state}>
              <span className={styles.lamp} aria-hidden="true" />
              <span className={styles.nodeName}>{check}</span>
              <span className={styles.nodeState}>{NODE_LABEL[state]}</span>
            </li>
          )
        })}
      </ol>

      <p className={styles.pathNote}>
        {onCount === 0
          ? COPY.SIGNAL_NONE
          : result === undefined
            ? COPY.SIGNAL_WAITING
            : stopped
              ? COPY.SIGNAL_REFUSED.replace('{check}', firstHit ?? '')
              : COPY.SIGNAL_PASSED}
      </p>
    </section>
  )
}

function LevelNote({ level }: { level: Level }): React.ReactElement {
  const off = CHECK_ORDER.filter((check) => !level.active_checks.includes(check))

  return (
    <section className={styles.levelNote}>
      <div className={styles.sectionHead}>
        <h2 className={styles.heading}>{COPY.TEACHES_LABEL}</h2>
      </div>
      <p className={styles.teaches}>{level.teaches}</p>
      {off.length > 0 && (
        <p className={styles.offList}>
          {COPY.DISABLED_PREFIX}: {off.join(', ')}
        </p>
      )}
      {level.number === ARENA.BOUNTY_LEVEL && (
        <p className={styles.bounty}>{COPY.BOUNTY_NOTE}</p>
      )}
    </section>
  )
}

function CensusCell({
  label,
  value,
  hot,
}: {
  label: string
  value: number
  hot: boolean
}): React.ReactElement {
  return (
    <div className={styles.cell} data-hot={hot}>
      <span className={styles.cellValue}>{value}</span>
      <span className={styles.cellLabel}>{label}</span>
    </div>
  )
}

function Specimen({
  ticket,
  sets,
}: {
  ticket: string
  sets: CodepointSets
}): React.ReactElement {
  const [revealed, setRevealed] = useState<boolean>(false)
  const counts = useMemo(() => census(ticket, sets), [ticket, sets])
  const hidden = hiddenTotal(counts)
  const parts = useMemo(
    () => (revealed ? segments(ticket, sets) : []),
    [revealed, ticket, sets]
  )

  return (
    <section className={styles.specimen}>
      <div className={styles.sectionHead}>
        <h2 className={styles.heading}>{COPY.SPECIMEN_HEADING}</h2>
        <button
          type="button"
          className={styles.textButton}
          data-on={revealed}
          aria-pressed={revealed}
          onClick={() => setRevealed((value) => !value)}
        >
          {revealed ? COPY.REVEAL_OFF : COPY.REVEAL_ON}
        </button>
      </div>

      <div className={styles.census}>
        <CensusCell
          label={COPY.CENSUS.GLYPHS}
          value={counts.glyphs}
          hot={false}
        />
        <CensusCell label={COPY.CENSUS.BYTES} value={counts.bytes} hot={false} />
        <CensusCell
          label={COPY.CENSUS.NON_ASCII}
          value={counts.nonAscii}
          hot={false}
        />
        <CensusCell
          label={COPY.CENSUS.TAG}
          value={counts.tag}
          hot={counts.tag > 0}
        />
        <CensusCell
          label={COPY.CENSUS.BIDI}
          value={counts.bidi}
          hot={counts.bidi > 0}
        />
        <CensusCell
          label={COPY.CENSUS.ZERO_WIDTH}
          value={counts.zeroWidth}
          hot={counts.zeroWidth > 0}
        />
      </div>

      {ticket.length === 0 ? (
        <p className={styles.note}>{COPY.SPECIMEN_EMPTY}</p>
      ) : (
        <p className={styles.note} data-loud={hidden > 0}>
          {hidden > 0 ? COPY.CENSUS_DIRTY : COPY.CENSUS_CLEAN}
        </p>
      )}

      {revealed && ticket.length > 0 && (
        <pre className={styles.reveal}>
          {parts.map((part) =>
            part.mark === null ? (
              <span key={part.start}>{part.text}</span>
            ) : (
              <mark
                key={part.start}
                className={styles.revealMark}
                data-mark={part.mark}
              >
                {part.mark === CENSUS_MARKS.TAG
                  ? part.text.codePointAt(0)?.toString(16)
                  : part.mark}
              </mark>
            )
          )}
        </pre>
      )}
    </section>
  )
}

function Findings({ alerts }: { alerts: Alert[] }): React.ReactElement {
  if (alerts.length === 0) {
    return <p className={styles.note}>{COPY.NO_RULES}</p>
  }

  return (
    <ul className={styles.alerts}>
      {alerts.map((alert, index) => (
        <li
          key={`${index}-${alert.check}-${alert.rule}`}
          className={styles.alert}
          data-hard={alert.hard}
        >
          <span className={styles.alertCheck}>{alert.check}</span>
          <span className={styles.alertRule}>{alert.rule}</span>
          <span className={styles.alertWeight}>{alert.weight}</span>
          <span className={styles.alertFlag}>
            {alert.hard ? COPY.HARD_MARK : ''}
          </span>
        </li>
      ))}
    </ul>
  )
}

function Result({ result }: { result: AttemptResponse }): React.ReactElement {
  const fired = firedAlerts(result)

  return (
    <section
      className={styles.result}
      data-refused={refused(result)}
      aria-live="polite"
    >
      <div className={styles.sectionHead}>
        <h2 className={styles.heading}>{COPY.RESULT_HEADING}</h2>
        <span className={styles.meta}>
          {COPY.ATTEMPTS_LABEL} {numeral(result.attempts)}
        </span>
      </div>

      <div className={styles.rulings}>
        <div className={styles.ruling} data-ruling={result.inbound_ruling}>
          <span className={styles.rulingLabel}>{COPY.INBOUND_LABEL}</span>
          <strong className={styles.rulingValue}>{result.inbound_ruling}</strong>
        </div>
        <div
          className={styles.ruling}
          data-ruling={result.outbound_ruling ?? 'none'}
        >
          <span className={styles.rulingLabel}>{COPY.OUTBOUND_LABEL}</span>
          <strong className={styles.rulingValue}>
            {result.outbound_ruling ?? COPY.UNREACHED}
          </strong>
        </div>
      </div>

      <div className={styles.seal} data-escaped={result.secret_escaped}>
        <span className={styles.sealLabel}>{COPY.SECRET_STATUS_LABEL}</span>
        <strong className={styles.sealValue}>
          {result.secret_escaped ? COPY.SECRET_ESCAPED : COPY.SECRET_CONTAINED}
        </strong>
      </div>

      <h3 className={styles.subHead}>{COPY.RULES_HEADING}</h3>
      <Findings alerts={fired} />

      <h3 className={styles.subHead}>{COPY.AGENT_HEADING}</h3>
      <pre className={styles.agent}>{result.reply_text || COPY.AGENT_EMPTY}</pre>

      <h3 className={styles.subHead}>{COPY.PROPOSALS_HEADING}</h3>
      {result.proposals.length === 0 ? (
        <p className={styles.note}>{COPY.NO_PROPOSALS}</p>
      ) : (
        <ul className={styles.proposals}>
          {result.proposals.map((proposal, index) => (
            <li key={`${index}-${proposal.name}`} className={styles.proposal}>
              <span className={styles.proposalName}>{proposal.name}</span>
              <span className={styles.proposalArgs}>
                {proposal.args.join(', ')}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

export function Component(): React.ReactElement {
  const [level, setLevel] = useState<number>(ARENA.FIRST_LEVEL)
  const [ticket, setTicket] = useState<string>('')

  const levels = useLevels()
  const session = useSession()
  const attempt = useAttempt()
  const codepoints = useCodepoints()

  const current = useMemo(
    () => levels.data?.levels.find((entry) => entry.number === level),
    [levels.data, level]
  )

  const canSubmit =
    session.data !== undefined &&
    ticket.length > 0 &&
    ticket.length <= ARENA.MAX_TICKET_CHARS &&
    !attempt.isPending

  const submit = (event: React.FormEvent): void => {
    event.preventDefault()
    if (session.data === undefined) {
      return
    }
    attempt.mutate({
      session_id: session.data.session_id,
      level,
      ticket,
    })
  }

  return (
    <div className={styles.page}>
      <header className={styles.masthead}>
        <div className={styles.brand}>
          <h1 className={styles.wordmark}>{COPY.TITLE}</h1>
          <p className={styles.tagline}>{COPY.TAGLINE}</p>
        </div>

        <dl className={styles.stats}>
          <div className={styles.stat}>
            <dt className={styles.statLabel}>{COPY.SESSION_LABEL}</dt>
            <dd className={styles.statValue}>
              {session.data?.session_id.slice(0, SESSION_ID_HEAD) ?? COPY.PENDING}
            </dd>
          </div>
          <div className={styles.stat}>
            <dt className={styles.statLabel}>{COPY.SECRET_LABEL}</dt>
            <dd className={styles.statValue}>
              {session.data === undefined
                ? COPY.PENDING
                : `${session.data.secret_length} ${COPY.CHARS}`}
            </dd>
          </div>
          <div className={styles.stat}>
            <dt className={styles.statLabel}>{COPY.LEVELS_LABEL}</dt>
            <dd className={styles.statValue}>
              {numeral(levels.data?.levels.length ?? 0)}
            </dd>
          </div>
        </dl>
      </header>

      <div className={styles.panel}>
        <nav className={styles.levelBar} aria-label={COPY.LEVELS_HEADING}>
          {levels.data?.levels.map((entry) => (
            <LevelButton
              key={entry.number}
              level={entry}
              selected={entry.number === level}
              onSelect={setLevel}
            />
          ))}
        </nav>

        <div className={styles.desk}>
          <section className={styles.work}>
            <form className={styles.form} onSubmit={submit}>
              <div className={styles.sectionHead}>
                <h2 className={styles.heading}>{COPY.TICKET_HEADING}</h2>
                <span className={styles.meta}>
                  {ticket.length} / {ARENA.MAX_TICKET_CHARS}
                </span>
              </div>
              <p className={styles.hint}>{COPY.TICKET_HINT}</p>
              <textarea
                id="ticket"
                className={styles.textarea}
                value={ticket}
                maxLength={ARENA.MAX_TICKET_CHARS}
                spellCheck={false}
                aria-label={COPY.TICKET_HEADING}
                onChange={(event) => setTicket(event.target.value)}
              />
              <div className={styles.controls}>
                <button
                  type="submit"
                  className={styles.submit}
                  disabled={!canSubmit}
                >
                  {attempt.isPending ? COPY.SUBMITTING : COPY.SUBMIT}
                </button>
                <span className={styles.levelTag}>
                  {numeral(level)}
                  {current ? ` / ${current.title}` : ''}
                </span>
              </div>
            </form>

            <Specimen
              ticket={ticket}
              sets={codepoints.data ?? FALLBACK_CODEPOINTS}
            />
          </section>

          <aside className={styles.side}>
            {current && <SignalPath level={current} result={attempt.data} />}
            {current && <LevelNote level={current} />}

            {attempt.isError && (
              <p className={styles.error}>{attemptMessage(attempt.error)}</p>
            )}

            {attempt.data ? (
              <Result result={attempt.data} />
            ) : (
              <p className={styles.awaiting}>{COPY.AWAITING}</p>
            )}
          </aside>
        </div>
      </div>
    </div>
  )
}

Component.displayName = 'Arena'
