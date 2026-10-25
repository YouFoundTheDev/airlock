/**
 * © https://github.com/YouFoundTheDev | 2026
 * shell.tsx
 */

import { Suspense } from 'react'
import { ErrorBoundary } from 'react-error-boundary'
import { Outlet } from 'react-router-dom'
import { COPY } from '@/config'
import styles from './shell.module.scss'

const SOURCE = 'https://github.com/YouFoundTheDev/airlock'

function ShellErrorFallback({ error }: { error: Error }): React.ReactElement {
  return (
    <div className={styles.error}>
      <h2 className={styles.errorHeading}>{COPY.ERRORS.DEFAULT}</h2>
      <pre className={styles.errorBody}>{error.message}</pre>
    </div>
  )
}

function ShellLoading(): React.ReactElement {
  return <div className={styles.loading}>{COPY.LOADING}</div>
}

export function Shell(): React.ReactElement {
  return (
    <div className={styles.frame}>
      <div className={styles.inner}>
        <main className={styles.main}>
          <ErrorBoundary FallbackComponent={ShellErrorFallback}>
            <Suspense fallback={<ShellLoading />}>
              <Outlet />
            </Suspense>
          </ErrorBoundary>
        </main>

        <footer className={styles.foot}>
          <span className={styles.footName}>{COPY.TITLE}</span>
          <span className={styles.footSpec}>{COPY.FOOTER_SPEC}</span>
          <span className={styles.footEnd}>
            <a className={styles.footLink} href={SOURCE}>
              {COPY.FOOTER_SOURCE}
            </a>
            <span>{COPY.FOOTER_LICENSE}</span>
          </span>
        </footer>
      </div>
    </div>
  )
}
