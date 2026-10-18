import { it, expect } from 'vitest'
import { validVitestReport } from '../scripts/gate.mjs'
it('V-r9f gate rejects zero execution, skipped, todo and invalid reports', () => {
  const good = { success: true, numPassedTests: 1, numFailedTests: 0, numPendingTests: 0, numTodoTests: 0 }
  expect(validVitestReport(good)).toBe(true)
  expect(validVitestReport({ ...good, numPassedTests: 0 })).toBe(false)
  expect(validVitestReport({ ...good, numPassedTests: 0, numPendingTests: 40 })).toBe(false)
  expect(validVitestReport({ ...good, numPendingTests: 1 })).toBe(false)
  expect(validVitestReport({ ...good, numFailedTests: 1 })).toBe(false)
  expect(validVitestReport({ ...good, numTodoTests: 1 })).toBe(false)
  expect(validVitestReport(null)).toBe(false)
})
