import { describe, expect, it } from 'vitest'
import { formatBytes, isReportReady, isRunning } from './api'

describe('Web 状态工具', () => {
  it('区分运行和报告就绪状态', () => {
    expect(isRunning('analyzing')).toBe(true)
    expect(isRunning('completed')).toBe(false)
    expect(isReportReady('partial')).toBe(true)
    expect(isReportReady('failed')).toBe(false)
  })

  it('以有界单位显示大报文大小', () => {
    expect(formatBytes(1024 ** 3)).toBe('1.00 GB')
    expect(formatBytes(20 * 1024 ** 2)).toBe('20.0 MB')
  })
})
