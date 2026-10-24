// ===================
// © https://github.com/YouFoundTheDev | 2026
// index.ts
// ===================

import { z } from 'zod'

export const alertSchema = z.object({
  check: z.string(),
  rule: z.string(),
  weight: z.string(),
  hard: z.boolean(),
})

export const levelSchema = z.object({
  number: z.number(),
  title: z.string(),
  teaches: z.string(),
  active_checks: z.array(z.string()),
})

export const levelsResponseSchema = z.object({
  levels: z.array(levelSchema),
})

export const sessionResponseSchema = z.object({
  session_id: z.string(),
  secret_length: z.number(),
})

export const proposalSchema = z.object({
  name: z.string(),
  args: z.array(z.string()),
})

export const attemptResponseSchema = z.object({
  level: levelSchema,
  inbound_ruling: z.string(),
  outbound_ruling: z.string().nullable(),
  reply_text: z.string(),
  proposals: z.array(proposalSchema),
  secret_escaped: z.boolean(),
  alerts: z.array(alertSchema),
  attempts: z.number(),
})

export const codepointsResponseSchema = z.object({
  tag: z.array(z.number()),
  bidi: z.array(z.number()),
  zero_width: z.array(z.number()),
})

export type Alert = z.infer<typeof alertSchema>
export type Level = z.infer<typeof levelSchema>
export type LevelsResponse = z.infer<typeof levelsResponseSchema>
export type SessionResponse = z.infer<typeof sessionResponseSchema>
export type Proposal = z.infer<typeof proposalSchema>
export type AttemptResponse = z.infer<typeof attemptResponseSchema>
export type CodepointsResponse = z.infer<typeof codepointsResponseSchema>

export interface AttemptRequest {
  session_id: string
  level: number
  ticket: string
}
