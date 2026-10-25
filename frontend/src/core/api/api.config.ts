// ===================
// © https://github.com/YouFoundTheDev | 2026
// api.config.ts
// ===================

import axios, { type AxiosInstance, isAxiosError } from 'axios'

import { transformAxiosError } from './errors'

const getBaseURL = (): string => {
  return import.meta.env.VITE_API_URL ?? '/api'
}

export const apiClient: AxiosInstance = axios.create({
  baseURL: getBaseURL(),
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
  withCredentials: true,
})

apiClient.interceptors.response.use(
  (response) => response,
  (error: unknown) => {
    if (isAxiosError(error)) {
      return Promise.reject(transformAxiosError(error))
    }
    return Promise.reject(error)
  }
)
