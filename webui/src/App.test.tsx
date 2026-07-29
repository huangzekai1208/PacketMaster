// 工作台关键导航和知识库入口的组件测试。
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { App, KnowledgeReferences } from './App'

const session = { session_id: 'session-1', title: '下载测速诊断', status: 'draft', created_at: '2026-07-26T00:00:00Z', updated_at: '2026-07-26T00:00:00Z' }

beforeEach(() => {
  localStorage.clear()
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input)
    const data = path.includes('/api/health') ? { status: 'ok', model_configured: true, tshark_configured: true } : path.includes('/api/knowledge/evaluation-status') ? { active_gate_passed: false, requested_mode: 'shadow', effective_mode: 'shadow', last_report: null } : path.includes('/api/knowledge') ? { items: [], total: 0, offset: 0, limit: 100 } : path.includes('/api/sessions/session-1') ? { session, messages: { items: [], total: 0, offset: 0, limit: 100 }, parameters: null } : { items: [session], total: 1, offset: 0, limit: 50 }
    return new Response(JSON.stringify({ ok: true, data }), { status: 200, headers: { 'Content-Type': 'application/json' } })
  }))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

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

it('可从工作台进入知识管理视图', async () => {
  render(<QueryClientProvider client={new QueryClient()}><App /></QueryClientProvider>)

  await screen.findByRole('button', { name: '知识库' })
  screen.getByRole('button', { name: '知识库' }).click()

  expect(await screen.findByRole('heading', { name: '知识库' })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: '导入知识' })).toBeInTheDocument()
  expect(screen.getByText('Active 门禁')).toBeInTheDocument()

  screen.getByRole('button', { name: '导入知识' }).click()
  expect(await screen.findByRole('button', { name: '选择本地文件' })).toBeInTheDocument()
})

it('发送普通消息时会在请求完成前立即显示在对话区', async () => {
  let resolveMessage: ((value: Response) => void) | undefined
  vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
    const path = String(input)
    if (path.includes('/messages')) return new Promise<Response>(resolve => { resolveMessage = resolve })
    const data = path.includes('/api/health') ? { status: 'ok', model_configured: true, tshark_configured: true } : path.includes('/api/sessions/session-1') ? { session, messages: { items: [], total: 0, offset: 0, limit: 100 }, parameters: null } : { items: [session], total: 1, offset: 0, limit: 50 }
    return Promise.resolve(new Response(JSON.stringify({ ok: true, data }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
  }))
  render(<QueryClientProvider client={new QueryClient()}><App /></QueryClientProvider>)

  const input = await screen.findByLabelText('对话输入')
  fireEvent.change(input, { target: { value: '请立即显示这条消息' } })
  fireEvent.click(screen.getByTitle('发送'))

  expect(screen.getByText('请立即显示这条消息')).toBeInTheDocument()
  expect(await screen.findByText('Thinking…')).toBeInTheDocument()
  resolveMessage?.(new Response(JSON.stringify({ ok: true, data: {} }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
})

it('选择报文后只添加附件，等待用户发送对话消息', async () => {
  const capture = { capture_id: 'capture-1', file_name: '测速.pcapng', size_bytes: 1024 }
  const requests: string[] = []
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input)
    requests.push(path)
    const data = path.includes('/api/captures/upload') ? capture : path.includes('/api/health') ? { status: 'ok', model_configured: true, tshark_configured: true } : path.includes('/api/sessions/session-1') ? { session, messages: { items: [], total: 0, offset: 0, limit: 100 }, parameters: null } : { items: [session], total: 1, offset: 0, limit: 50 }
    return new Response(JSON.stringify({ ok: true, data }), { status: 200, headers: { 'Content-Type': 'application/json' } })
  }))
  render(<QueryClientProvider client={new QueryClient()}><App /></QueryClientProvider>)

  await screen.findByLabelText('对话输入')
  screen.getByTitle('加载报文').click()
  fireEvent.change(screen.getByLabelText('选择本地报文'), { target: { files: [new File(['capture'], '测速.pcapng', { type: 'application/octet-stream' })] } })

  expect(await screen.findByLabelText('移除报文附件')).toBeInTheDocument()
  expect(requests.some(path => path.includes('/messages'))).toBe(false)
})
