// 工作台关键导航和知识库入口的组件测试。
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { AnalysisCompletionNotice, AnalysisFailurePanel, App, KnowledgeReferences, LLMUsageBadge, RagMessageTrace } from './App'

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
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

it('呈现工作台、历史会话和任务视图标签', async () => {
  render(<QueryClientProvider client={new QueryClient()}><App /></QueryClientProvider>)
  expect(screen.getByText('PacketMaster')).toBeInTheDocument()
  expect(screen.getByRole('navigation', { name: '任务视图' })).toBeInTheDocument()
  await waitFor(() => expect(screen.getByText('下载测速诊断')).toBeInTheDocument())
  const createSession = screen.getByRole('button', { name: '新建会话' })
  expect(createSession.closest('.sessions')).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: '新建任务' })).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: /报告/ })).toBeInTheDocument()
  const input = screen.getByLabelText('对话输入')
  expect(input).toBeInTheDocument()
  expect(input.closest('.chat-view')).toHaveClass('chat-view-initial')
  expect(screen.getByText('你好，我是 PacketMaster')).toBeInTheDocument()
})

it('支持切换到通用卡顿模式并携带分析意图', async () => {
  let submitted = ''
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input)
    if (init?.method === 'POST' && path.includes('/messages')) submitted = String(init.body)
    const data = path.includes('/api/health')
      ? { status: 'ok', model_configured: true, tshark_configured: true }
      : path.includes('/api/sessions/session-1')
        ? { session, messages: { items: [], total: 0, offset: 0, limit: 100 }, parameters: null }
        : { items: [session], total: 1, offset: 0, limit: 50 }
    return new Response(JSON.stringify({ ok: true, data }), { status: 200, headers: { 'Content-Type': 'application/json' } })
  }))
  render(<QueryClientProvider client={new QueryClient()}><App /></QueryClientProvider>)

  const speed = await screen.findByRole('button', { name: '测速分析' })
  const stall = screen.getByRole('button', { name: '通用卡顿' })
  expect(speed).toHaveAttribute('aria-pressed', 'true')
  fireEvent.click(stall)
  expect(stall).toHaveAttribute('aria-pressed', 'true')
  expect(localStorage.getItem('packetmaster.analysis-mode.session-1')).toBe('stall')

  fireEvent.change(screen.getByLabelText('对话输入'), { target: { value: '12 秒左右开始变慢' } })
  fireEvent.click(screen.getByTitle('发送'))

  await waitFor(() => expect(submitted).toContain('"mode":"stall"'))
  expect(submitted).toContain('12 秒左右开始变慢')
})

it('卡顿报告展示多协议关联且不展示带宽指标', async () => {
  localStorage.setItem('packetmaster.session', 'session-1')
  vi.stubGlobal('EventSource', class { addEventListener() {} close() {} })
  const completedSession = { ...session, status: 'completed', current_analysis_id: 'analysis-1' }
  const analysis = { analysis_id: 'analysis-1', session_id: 'session-1', status: 'completed', stage_message: '分析完成', progress_fraction: 1, capture: { capture_id: 'capture-1', file_name: 'stall.pcapng', size_bytes: 1024 }, mode: 'stall', standard_bandwidth_mbps: 1, actual_bandwidth_mbps: 1, target: 'both', created_at: '2026-08-11T00:00:00Z', updated_at: '2026-08-11T00:00:01Z', elapsed_seconds: 1 }
  const report = { mode: 'stall', analysis_id: 'analysis-1', primary_cause: 'PlayStation Network 登录链路异常集中在“域名解析”阶段', candidate_causes: [], key_evidence: [], confidence: 88, coverage_summary: { complete: true, truncated: false }, stall_events: [], protocol_summary: { tcp_flow_count: 1 }, endpoint_summary: [{ ip: '198.51.100.20', scope: 'public', packets: 20, protocols: ['TLSv1.3'], domains: ['auth.api.playstation.com'], sni: ['auth.api.playstation.com'] }], dns_summary: { failure_count: 1, unanswered_count: 1, latency_ms: { p95: 800 }, domains: [{ name: 'auth.api.playstation.com', answer_ips: ['198.51.100.20'] }] }, tls_summary: { alert_count: 0, sni: [{ name: 'auth.api.playstation.com', endpoint_ips: ['198.51.100.20'] }] }, http_summary: { error_response_count: 0, latency_ms: { p95: 120 } }, udp_summary: { quic_packet_count: 4 }, keyword_summary: {}, user_context: { summary: '游戏、登录/认证', tags: ['game', 'login'] }, business_analysis: { targeted: true, service_name: 'PlayStation Network', action: 'login', conclusion: 'PlayStation Network 登录链路异常集中在“域名解析”阶段', observed_hosts: ['auth.api.playstation.com'], stages: [{ stage: 'dns', name: '域名解析', status: 'failed', evidence: '发现 1 个相关域名，失败 1，未响应 1' }, { stage: 'transport', name: '网络连接', status: 'not_observed', evidence: 'SYN/SYN-ACK 0/0' }, { stage: 'tls', name: 'TLS 安全协商', status: 'not_observed', evidence: 'ClientHello/ServerHello 0/0' }, { stage: 'authentication', name: '账号认证', status: 'not_observed', evidence: '认证内容不可见' }] }, limitations: [], troubleshooting_steps: [], optimization_suggestions: [], analysis_metadata: {} }
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input)
    const data = path.endsWith('/report') ? { analysis_id: 'analysis-1', report }
      : path.includes('/api/analyses/analysis-1/chat') ? { items: [], total: 0, offset: 0, limit: 100 }
        : path.includes('/api/analyses/analysis-1') ? { analysis, report_available: true, recoverable: false, suggested_action: '' }
          : path.includes('/api/health') ? { status: 'ok', model_configured: true, tshark_configured: true }
            : path.includes('/api/sessions/session-1') ? { session: completedSession, messages: { items: [], total: 0, offset: 0, limit: 100 }, parameters: null }
              : { items: [completedSession], total: 1, offset: 0, limit: 50 }
    return new Response(JSON.stringify({ ok: true, data }), { status: 200, headers: { 'Content-Type': 'application/json' } })
  }))
  render(<QueryClientProvider client={new QueryClient()}><App /></QueryClientProvider>)

  fireEvent.click(await screen.findByRole('button', { name: /报告/ }))

  expect((await screen.findAllByText('PlayStation Network 登录链路异常集中在“域名解析”阶段')).length).toBeGreaterThan(0)
  expect(screen.getByText('账号认证')).toBeInTheDocument()
  expect(screen.getAllByText('auth.api.playstation.com').length).toBeGreaterThan(0)
  expect(screen.getByText('198.51.100.20')).toBeInTheDocument()
  expect(screen.queryByText('标准带宽')).not.toBeInTheDocument()
  expect(screen.queryByText('实际带宽')).not.toBeInTheDocument()
  expect(screen.queryByText('达标率')).not.toBeInTheDocument()
})

it('展示模型 Token、成本和调用明细', () => {
  render(<LLMUsageBadge costConfigured value={{
    call_count: 3,
    succeeded_count: 3,
    failed_count: 0,
    retry_count: 1,
    calls_with_token_usage: 3,
    input_tokens: 10_000,
    output_tokens: 2_345,
    total_tokens: 12_345,
    estimated_cost_usd: 0.0123,
    operation_counts: { general_chat: 3 },
  }} />)

  expect(screen.getByText('12K Token')).toBeInTheDocument()
  expect(screen.getAllByText('$0.0123')).toHaveLength(2)
  expect(screen.getByText('10,000')).toBeInTheDocument()
  expect(screen.getByText('2,345')).toBeInTheDocument()
})

it('展示分析失败原因和受控技术详情', () => {
  render(<AnalysisFailurePanel value={{
    analysis: {
      analysis_id: 'analysis-1', session_id: 'session-1', status: 'failed',
      stage_message: '分析失败', capture: { capture_id: 'capture-1', file_name: 'test.pcap', size_bytes: 10 },
      mode: 'speed',
      standard_bandwidth_mbps: 1000, actual_bandwidth_mbps: 400, target: 'download',
      created_at: '2026-08-05T00:00:00Z', updated_at: '2026-08-05T00:00:01Z', elapsed_seconds: 1,
      error_code: 'MODEL_CALL_FAILED',
    },
    report_available: false,
    recoverable: true,
    error_message: '模型调用失败',
    suggested_action: '检查模型配置后重试。',
    error_details: { exception_type: 'TimeoutError', attempts: 2 },
  }} />)

  expect(screen.getByRole('alert', { name: '分析错误详情' })).toBeInTheDocument()
  expect(screen.getByText('MODEL_CALL_FAILED')).toBeInTheDocument()
  expect(screen.getByText('模型调用失败')).toBeInTheDocument()
  expect(screen.getByText(/exception_type=TimeoutError/)).toBeInTheDocument()
  expect(screen.getByText('检查模型配置后重试。')).toBeInTheDocument()
})

it('分析完成后展示总耗时和处理报文数', () => {
  render(<AnalysisCompletionNotice value={{
    analysis_id: 'analysis-1', session_id: 'session-1', status: 'completed',
    stage_message: '分析完成', capture: { capture_id: 'capture-1', file_name: 'test.pcap', size_bytes: 10 },
    mode: 'speed',
    standard_bandwidth_mbps: 1000, actual_bandwidth_mbps: 400, target: 'download',
    created_at: '2026-08-05T00:00:00Z', updated_at: '2026-08-05T00:01:05Z',
    elapsed_seconds: 65.2, processed_packets: 12_345,
  }} />)

  expect(screen.getByRole('status', { name: '分析完成状态' })).toBeInTheDocument()
  expect(screen.getByText('总耗时 1 分 5 秒')).toBeInTheDocument()
  expect(screen.getByText('处理 12,345 个报文')).toBeInTheDocument()
})

it('可从会话任务栏删除历史会话', async () => {
  const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true)
  const fetchMock = vi.mocked(fetch)
  render(<QueryClientProvider client={new QueryClient()}><App /></QueryClientProvider>)

  const deleteButton = await screen.findByRole('button', { name: '删除会话 下载测速诊断' })
  fireEvent.click(deleteButton)

  expect(confirm).toHaveBeenCalledWith('确定删除“下载测速诊断”吗？此操作无法恢复。')
  await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/sessions/session-1', expect.objectContaining({ method: 'DELETE' })))
})

it('关闭会话栏后可从顶部栏重新展开', async () => {
  render(<QueryClientProvider client={new QueryClient()}><App /></QueryClientProvider>)

  const collapse = await screen.findByRole('button', { name: '收起会话' })
  fireEvent.click(collapse)
  const expand = await screen.findByRole('button', { name: '展开会话栏' })
  fireEvent.click(expand)

  expect(await screen.findByRole('button', { name: '收起会话' })).toBeInTheDocument()
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

it('展示普通对话使用的 RAG 引用和 reranker 相关度', () => {
  render(<RagMessageTrace message={{
    message_id: 'message-1',
    session_id: 'session-1',
    message_type: 'assistant',
    content: '相对序列号只是显示方式。',
    created_at: '2026-07-31T00:00:00Z',
    evidence_count: 0,
    rag_status: 'used',
    rag_citations: [{
      knowledge_id: 'wireshark.tcp',
      title: 'Wireshark TCP 分析',
      chunk_id: 'wireshark.tcp:v1:c3',
      reranker_score: 0.9321,
    }],
  }} />)

  expect(screen.getByRole('region', { name: 'RAG 检索状态' })).toBeInTheDocument()
  expect(screen.getByText('RAG 已使用')).toBeInTheDocument()
  expect(screen.getByText('Wireshark TCP 分析')).toBeInTheDocument()
  expect(screen.getByText('wireshark.tcp:v1:c3')).toBeInTheDocument()
  expect(screen.getByText('相关度 0.9321')).toBeInTheDocument()
})

it('展示 RAG 降级且不伪造 reranker 分数', () => {
  render(<RagMessageTrace message={{
    message_id: 'message-2',
    session_id: 'session-1',
    message_type: 'assistant',
    content: '仍然返回普通回答。',
    created_at: '2026-07-31T00:00:00Z',
    evidence_count: 0,
    rag_status: 'degraded',
    rag_reason: '模型重排序降级：RERANK_TIMEOUT',
    rag_citations: [{
      knowledge_id: 'wireshark.tcp',
      title: 'Wireshark TCP 分析',
      chunk_id: 'wireshark.tcp:v1:c3',
    }],
  }} />)

  expect(screen.getByText('RAG 已降级')).toBeInTheDocument()
  expect(screen.getByText('相关度不可用')).toBeInTheDocument()
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

it('选择知识文件后自动预填可编辑的导入信息', async () => {
  render(<QueryClientProvider client={new QueryClient()}><App /></QueryClientProvider>)

  await screen.findByRole('button', { name: '知识库' })
  screen.getByRole('button', { name: '知识库' }).click()
  const importButton = await screen.findByRole('button', { name: '导入知识' })
  importButton.click()
  const file = new File(['# TCP 窗口排查手册\n\n用于定位下载吞吐不足。'], 'window-case.md', { type: 'text/markdown' })
  fireEvent.change(await screen.findByLabelText('知识文件'), { target: { files: [file] } })

  await waitFor(() => expect(screen.getByLabelText('标题')).toHaveValue('TCP 窗口排查手册'))
  expect(screen.getByLabelText('知识 ID')).toHaveValue('knowledge.window-case')
  expect(screen.getByLabelText('类型')).toHaveValue('case')
  expect(screen.getByLabelText('权威性')).toHaveValue('medium_high')
  expect(screen.getByLabelText('来源名称')).toHaveValue('window-case.md')
  expect(screen.getByLabelText('摘要')).toHaveValue('用于定位下载吞吐不足。')
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
  await waitFor(() => expect(input.closest('.chat-view')).not.toHaveClass('chat-view-initial'))
  expect(await screen.findByText('Thinking…')).toBeInTheDocument()
  resolveMessage?.(new Response(JSON.stringify({ ok: true, data: {} }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
})

it('打开页面时自动丢弃已经失效的本地会话 ID', async () => {
  localStorage.setItem('packetmaster.session', 'deleted-session')
  const requests: string[] = []
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input)
    if (init?.method === 'POST' && path.includes('/messages')) requests.push(path)
    if (path.includes('/api/sessions/deleted-session')) {
      return new Response(JSON.stringify({ ok: false, error: { code: 'SESSION_NOT_FOUND', message: '会话不存在', suggested_action: '请选择其他会话。', recoverable: true } }), { status: 404, headers: { 'Content-Type': 'application/json' } })
    }
    const data = path.includes('/api/health')
      ? { status: 'ok', model_configured: true, tshark_configured: true }
      : path.includes('/api/sessions/session-1')
        ? { session, messages: { items: [], total: 0, offset: 0, limit: 100 }, parameters: null }
        : { items: [session], total: 1, offset: 0, limit: 50 }
    return new Response(JSON.stringify({ ok: true, data }), { status: 200, headers: { 'Content-Type': 'application/json' } })
  }))
  render(<QueryClientProvider client={new QueryClient()}><App /></QueryClientProvider>)

  await screen.findByLabelText('对话输入')
  await waitFor(() => expect(localStorage.getItem('packetmaster.session')).toBe('session-1'))
  const input = screen.getByLabelText('对话输入')
  fireEvent.change(input, { target: { value: '测试有效会话' } })
  fireEvent.click(screen.getByTitle('发送'))

  await waitFor(() => expect(requests).toContain('/api/sessions/session-1/messages'))
  expect(requests).not.toContain('/api/sessions/deleted-session/messages')
})

it('初始会话发送失败时显示错误并恢复输入内容', async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input)
    if (init?.method === 'POST' && path.includes('/messages')) {
      return new Response(JSON.stringify({ ok: false, error: { code: 'REQUEST_FAILED', message: '消息发送失败', suggested_action: '请检查连接后重试。', recoverable: true } }), { status: 503, headers: { 'Content-Type': 'application/json' } })
    }
    const data = path.includes('/api/health')
      ? { status: 'ok', model_configured: true, tshark_configured: true }
      : path.includes('/api/sessions/session-1')
        ? { session, messages: { items: [], total: 0, offset: 0, limit: 100 }, parameters: null }
        : { items: [session], total: 1, offset: 0, limit: 50 }
    return new Response(JSON.stringify({ ok: true, data }), { status: 200, headers: { 'Content-Type': 'application/json' } })
  }))
  render(<QueryClientProvider client={new QueryClient()}><App /></QueryClientProvider>)

  const input = await screen.findByLabelText('对话输入')
  fireEvent.change(input, { target: { value: '不能丢失的消息' } })
  fireEvent.click(screen.getByTitle('发送'))

  expect(await screen.findByText('消息发送失败')).toBeInTheDocument()
  expect(screen.getByText('请检查连接后重试。')).toBeInTheDocument()
  expect(input).toHaveValue('不能丢失的消息')
  expect(input.closest('.chat-view')).not.toHaveClass('chat-view-initial')
})

it('报告完成后的追问也会在请求完成前立即显示在对话区', async () => {
  let resolveQuestion: ((value: Response) => void) | undefined
  vi.stubGlobal('EventSource', class { addEventListener() {} close() {} })
  const completedSession = { ...session, status: 'completed', current_analysis_id: 'analysis-1' }
  const analysis = { analysis_id: 'analysis-1', session_id: 'session-1', status: 'completed', stage_message: '', progress_fraction: 1, capture: { capture_id: 'capture-1', file_name: '测速.pcapng', size_bytes: 1024 }, mode: 'speed', standard_bandwidth_mbps: 100, actual_bandwidth_mbps: 80, target: 'download', created_at: '2026-07-26T00:00:00Z', updated_at: '2026-07-26T00:00:00Z', elapsed_seconds: 1 }
  vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input)
    if (path.includes('/api/analyses/analysis-1/chat') && init?.method === 'POST') return new Promise<Response>(resolve => { resolveQuestion = resolve })
    const data = path.includes('/api/analyses/analysis-1/chat') ? { items: [], total: 0, offset: 0, limit: 100 } : path.includes('/api/analyses/analysis-1') ? { analysis, report_available: true, recoverable: false, suggested_action: '' } : path.includes('/api/health') ? { status: 'ok', model_configured: true, tshark_configured: true } : path.includes('/api/sessions/session-1') ? { session: completedSession, messages: { items: [], total: 0, offset: 0, limit: 100 }, parameters: null } : { items: [completedSession], total: 1, offset: 0, limit: 50 }
    return Promise.resolve(new Response(JSON.stringify({ ok: true, data }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
  }))
  render(<QueryClientProvider client={new QueryClient()}><App /></QueryClientProvider>)

  const input = await screen.findByPlaceholderText('有问题，尽管问')
  fireEvent.change(input, { target: { value: '请解释丢包原因' } })
  fireEvent.click(screen.getByTitle('发送'))

  expect(await screen.findByText('请解释丢包原因')).toBeInTheDocument()
  resolveQuestion?.(new Response(JSON.stringify({ ok: true, data: { turn_id: 'turn-1', analysis_id: 'analysis-1', question: '请解释丢包原因', answer: '这是正式回答。', citations: [], limitations: [], suggestions: [], created_at: '2026-07-26T00:00:01Z' } }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
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
  screen.getByTitle('选择报文文件').click()
  fireEvent.change(screen.getByLabelText('选择本地报文'), { target: { files: [new File(['capture'], '测速.pcapng', { type: 'application/octet-stream' })] } })

  expect(await screen.findByLabelText('移除报文附件')).toBeInTheDocument()
  expect(requests.some(path => path.includes('/messages'))).toBe(false)
})
