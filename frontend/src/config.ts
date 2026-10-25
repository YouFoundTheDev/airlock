// ===================
// © https://github.com/YouFoundTheDev | 2026
// config.ts
// ===================

export const API_ENDPOINTS = {
  ARENA: {
    LEVELS: '/levels',
    SESSION: '/session',
    ATTEMPT: '/attempt',
    CODEPOINTS: '/codepoints',
  },
} as const

export const QUERY_KEYS = {
  LEVELS: ['levels'] as const,
  SESSION: ['session'] as const,
  CODEPOINTS: ['codepoints'] as const,
} as const

export const ROUTES = {
  HOME: '/',
} as const

export const STORAGE_KEYS = {
  UI: 'ui-storage',
  SESSION: 'airlock-session',
} as const

export const QUERY_CONFIG = {
  STALE_TIME: {
    USER: 1000 * 60 * 5,
    STATIC: Number.POSITIVE_INFINITY,
    FREQUENT: 1000 * 30,
  },
  GC_TIME: {
    DEFAULT: 1000 * 60 * 30,
    LONG: 1000 * 60 * 60,
  },
  RETRY: {
    DEFAULT: 1,
    NONE: 0,
  },
} as const

export const HTTP_STATUS = {
  OK: 200,
  BAD_REQUEST: 400,
  NOT_FOUND: 404,
  PAYLOAD_TOO_LARGE: 413,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER: 500,
} as const

export const TOAST = {
  POSITION: 'top-right',
  DURATION: 2000,
} as const

export const ARENA = {
  FIRST_LEVEL: 1,
  LAST_LEVEL: 6,
  BOUNTY_LEVEL: 6,
  MAX_TICKET_CHARS: 4000,
} as const

export const CHECK_ORDER = [
  'residue',
  'phrasing',
  'fence',
  'grant',
  'spill',
] as const

export const RULING = {
  PERMIT: 'permit',
  REFUSE: 'refuse',
} as const

export const RULE_CHECK_MUTED = 'check-muted'

export const SEVERITY_WEIGHT = {
  INFO: 0,
  LOW: 1,
  MODERATE: 2,
  HIGH: 3,
  CRITICAL: 4,
} as const

export const SEVERITY_MAX_WEIGHT = 4

export const SEVERITY_SCALE_OFFSET = 1

export const NUMERAL_PAD = 2

export const SESSION_ID_HEAD = 8

// The engine is the source of truth for these sets and serves them
// from /api/codepoints. What follows is only the pre-fetch fallback,
// and it is kept identical to the backend tuples on purpose: two
// independent definitions of "invisible" means the panel a player
// reads and the check that enforces disagree.
export const CODEPOINT_CLASSES = {
  TAG: { LOW: 0xe0000, HIGH: 0xe007f },
  BIDI: [
    0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067,
    0x2068, 0x2069,
  ],
  ZERO_WIDTH: [0x200b, 0x200c, 0x200d, 0x2060, 0xfeff],
  ASCII_HIGH: 0x7f,
} as const

export const CENSUS_MARKS = {
  TAG: 'TAG',
  BIDI: 'BIDI',
  ZERO_WIDTH: 'ZW',
} as const

export type CensusMark = (typeof CENSUS_MARKS)[keyof typeof CENSUS_MARKS]

export const COPY = {
  TITLE: 'airlock',
  TAGLINE: 'Untrusted input in. Authorized effects out.',

  LOADING: 'Loading…',
  PENDING: 'opening…',

  SESSION_LABEL: 'session',
  SECRET_LABEL: 'secret',
  LEVELS_LABEL: 'levels',
  CHARS: 'chars',

  LEVELS_HEADING: 'Choose a level',
  TEACHES_LABEL: 'What this level teaches',
  DISABLED_PREFIX: 'Off at this level',
  BOUNTY_NOTE: 'Every check is on. A bypass here is a real finding.',

  TICKET_HEADING: 'Support ticket',
  TICKET_HINT: 'You write this. The agent reads it as untrusted content.',
  SUBMIT: 'Send ticket',
  SUBMITTING: 'Sending…',

  SPECIMEN_HEADING: 'What is actually in the text',
  SPECIMEN_EMPTY: 'Type a ticket and the census updates live.',
  REVEAL_ON: 'Reveal invisible characters',
  REVEAL_OFF: 'Hide invisible characters',
  CENSUS: {
    GLYPHS: 'glyphs',
    BYTES: 'utf-8 bytes',
    NON_ASCII: 'non-ascii',
    TAG: 'tag block',
    BIDI: 'bidi controls',
    ZERO_WIDTH: 'zero width',
  },
  CENSUS_CLEAN: 'Nothing hidden in this text.',
  CENSUS_DIRTY: 'This text carries characters you cannot see.',

  SIGNAL_HEADING: 'Signal path',
  SIGNAL_ON: 'on',
  SIGNAL_OFF: 'off',
  SIGNAL_HIT: 'fired',
  SIGNAL_STOP: 'stopped',
  SIGNAL_PASS: 'passed',
  SIGNAL_WAITING: 'The path lights up when a ticket comes back.',
  SIGNAL_PASSED: 'Every enabled check passed this request.',
  SIGNAL_REFUSED: 'Refused at {check}.',
  SIGNAL_NONE: 'No checks are enabled at this level. Nothing is enforced.',

  RESULT_HEADING: 'Result',
  ATTEMPTS_LABEL: 'attempt',
  INBOUND_LABEL: 'inbound',
  OUTBOUND_LABEL: 'outbound',
  UNREACHED: 'not reached',
  RULES_HEADING: 'Rules fired',
  NO_RULES: 'No rules fired.',
  HARD_MARK: 'hard',

  SECRET_ESCAPED: 'Secret escaped',
  SECRET_CONTAINED: 'Secret contained',
  SECRET_STATUS_LABEL: 'secret',
  AGENT_HEADING: 'Agent reply',
  AGENT_EMPTY: 'No reply. A check stopped the request.',
  PROPOSALS_HEADING: 'Proposed actions',
  NO_PROPOSALS: 'No actions proposed.',
  AWAITING: 'Nothing sent yet.',

  FOOTER_SPEC: 'Five checks. Three hard guarantees. One scored.',
  FOOTER_SOURCE: 'source',
  FOOTER_LICENSE: 'AGPL-3.0',

  ERRORS: {
    [HTTP_STATUS.PAYLOAD_TOO_LARGE]: 'That ticket is too long.',
    [HTTP_STATUS.TOO_MANY_REQUESTS]: 'Too many attempts. Wait a moment.',
    [HTTP_STATUS.NOT_FOUND]:
      'That session is gone. A fresh one is open — send the ticket again.',
    DEFAULT: 'Something broke on our side.',
  },
} as const

export type Route = typeof ROUTES
export type CheckName = (typeof CHECK_ORDER)[number]
