import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { App, KnowledgeReferences } from './App'

const session = { session_id: 'session-1', title: '下载测速诊断', status: 'draft', created_at: '2026-07-26T00:00:00Z', updated_at: '2026-07-26T00:00:00Z' }

beforeEach(() => {
  localStorage.clear()
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input)
    const data = path.includes('/api/health') ? { status: 'ok', model_configured: true, tshark_configured: true } : path.includes('/api/sessions/session-1') ? { session, messages: { items: [], total: 0, offset: 0, limit: 100 }, parameters: null } : { items: [session], total: 1, offset: 0, limit: 50 }
    return new Response(JSON.stringify({ ok: true, data }), { status: 200, headers: { 'Content-Type': 'application/json' } })
  }))
})

afterEach(() => vi.unstubAllGlobals())

it('呈现工作台、历史会话和任务视图标签', async () => {
  render(<QueryClientProvider client={new QueryClient()}><App /></QueryClientProvider>)
  expect(screen.getByText('PacketMaster')).toBeInTheDocument()
  expect(screen.getByRole('navigation', { name: '任务视图' })).toBeInTheDocument()
  await waitFor(() => expect(screen.getByText('下载测速诊断')).toBeInTheDocument())
  expect(screen.getByRole('button', { name: /报告/ })).toBeInTheDocument()
  expect(screen.getByLabelText('对话输入')).toBeInTheDocument()
})

it('将知识经验引用与报文证据分区展示', () => {
  render(<KnowledgeReferences value={[{
    knowledge_id: 'rfc.window',
    version_id: 'rfc.window:v1',
    chunk_id: 'rfc.window:v1:c1',
    title: 'TCP 窗口机制',
    knowledge_type: 'standard',
    source_name: 'RFC',
    supported_statement: '窗口会限制在途数据量',
    supporting_quote: '接收窗口会限制在途未确认数据量。',
  }]} />)

  expect(screen.getByRole('region', { name: '知识经验引用' })).toBeInTheDocument()
  expect(screen.getByText('TCP 窗口机制')).toBeInTheDocument()
  expect(screen.getByText(/rfc.window:v1/)).toBeInTheDocument()
})
