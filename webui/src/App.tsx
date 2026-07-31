// 主工作台：会话、分析进度、报表视图、报文选择与知识库入口。
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { EChartsOption } from 'echarts'
import { Activity, BarChart3, BookOpen, ChevronLeft, ChevronRight, FileSearch, FileUp, Menu, MessageSquare, Network, PanelLeft, PanelRight, Plus, RefreshCw, Send, Square, Trash2, X } from 'lucide-react'
import { ChangeEvent, CSSProperties, FormEvent, lazy, PointerEvent as ReactPointerEvent, Suspense, useEffect, useMemo, useRef, useState } from 'react'
import { Analysis, api, ApiFailure, Capture, ChatTurn, Evidence, formatBytes, isReportReady, isRunning, KnowledgeCitation, Metrics, Page, Parameters, Session, SessionDetail, TaskStatus } from './api'
import { KnowledgeManagement } from './KnowledgeManagement'
const Chart = lazy(() => import('./Chart'))

type Tab = 'chat' | 'report' | 'metrics' | 'flows' | 'evidence'
const statusText: Record<TaskStatus, string> = { draft: '收集参数', awaiting_confirmation: '待确认', queued: '排队中', validating: '校验中', analyzing: '分析报文', reasoning: '生成原因', verifying: '复核证据', reporting: '生成报告', completed: '已完成', partial: '部分完成', failed: '失败', cancelled: '已取消', interrupted: '已中断' }
const targetText = { download: '下载', upload: '上行', both: '上行 + 下载' }
const replyStatusLabels = ['Thinking…', 'Cooking…', 'Reviewing context…', 'Preparing reply…']
const sidebarMinWidth = 180
const workspaceMinWidth = 440

export function App() {
  // 会话 ID 持久化在浏览器本地；服务端仍是任务和报文引用的唯一可信来源。
  const client = useQueryClient()
  const [selected, setSelected] = useState(() => localStorage.getItem('packetmaster.session') ?? '')
  const [tab, setTab] = useState<Tab>('chat')
  const [leftOpen, setLeftOpen] = useState(() => innerWidth > 800)
  const [rightOpen, setRightOpen] = useState(() => innerWidth > 800)
  // 侧栏宽度保存到浏览器本地，拖动分隔条后下次打开仍保持用户的布局习惯。
  const [leftWidth, setLeftWidth] = useState(() => readSidebarWidth('packetmaster.sidebar.left', 260))
  const [rightWidth, setRightWidth] = useState(() => readSidebarWidth('packetmaster.sidebar.right', 320))
  const [pendingCapture, setPendingCapture] = useState<Capture | undefined>()
  const captureFileInput = useRef<HTMLInputElement>(null)
  const [knowledgeOpen, setKnowledgeOpen] = useState(false)
  const autoCreated = useRef(false)
  const sessions = useQuery({ queryKey: ['sessions'], queryFn: api.sessions })
  const create = useMutation({ mutationFn: api.createSession, onSuccess: (value) => { setSelected(value.session_id); setPendingCapture(undefined); client.invalidateQueries({ queryKey: ['sessions'] }) } })
  const removeSession = useMutation({
    mutationFn: api.deleteSession,
    onSuccess: (_result, sessionId) => {
      const next = sessions.data?.items.find(item => item.session_id !== sessionId)
      if (selected === sessionId) setSelected(next?.session_id ?? '')
      client.removeQueries({ queryKey: ['session', sessionId] })
      client.invalidateQueries({ queryKey: ['sessions'] })
    },
    onError: (error: Error) => window.alert(error.message),
  })
  useEffect(() => { if (!selected && sessions.data?.items[0]) setSelected(sessions.data.items[0].session_id) }, [selected, sessions.data])
  useEffect(() => { if (sessions.data?.total === 0 && !autoCreated.current) { autoCreated.current = true; create.mutate() } }, [sessions.data?.total, create])
  useEffect(() => { if (selected) localStorage.setItem('packetmaster.session', selected); else localStorage.removeItem('packetmaster.session') }, [selected])
  useEffect(() => { localStorage.setItem('packetmaster.sidebar.left', String(leftWidth)) }, [leftWidth])
  useEffect(() => { localStorage.setItem('packetmaster.sidebar.right', String(rightWidth)) }, [rightWidth])
  const detail = useQuery({ queryKey: ['session', selected], queryFn: () => api.session(selected), enabled: Boolean(selected) })
  const analysisId = detail.data?.session.current_analysis_id
  const analysis = useQuery({ queryKey: ['analysis', analysisId], queryFn: () => api.analysis(analysisId!), enabled: Boolean(analysisId), refetchInterval: ({ state }) => isRunning(state.data?.analysis.status) ? 1500 : false })
  useAnalysisEvents(analysisId, client)
  const health = useQuery({ queryKey: ['health'], queryFn: api.health, refetchInterval: 15_000 })
  const attachCapture = useMutation({ mutationFn: api.uploadCapture, onSuccess: setPendingCapture })
  const chooseCapture = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (file) attachCapture.mutate(file)
  }
  const openCapturePicker = () => captureFileInput.current?.click()
  const refresh = () => { client.invalidateQueries({ queryKey: ['session', selected] }); client.invalidateQueries({ queryKey: ['analysis', analysisId] }); client.invalidateQueries({ queryKey: ['sessions'] }) }
  const beginResize = (side: 'left' | 'right', event: ReactPointerEvent<HTMLDivElement>) => {
    const startX = event.clientX
    const startWidth = side === 'left' ? leftWidth : rightWidth
    event.currentTarget.setPointerCapture(event.pointerId)
    const updateWidth = (clientX: number) => {
      const delta = clientX - startX
      const otherWidth = side === 'left' ? rightWidth : leftWidth
      const maximum = Math.max(sidebarMinWidth, window.innerWidth - otherWidth - workspaceMinWidth)
      const nextWidth = Math.round(Math.min(maximum, Math.max(sidebarMinWidth, startWidth + (side === 'left' ? delta : -delta))))
      if (side === 'left') setLeftWidth(nextWidth)
      else setRightWidth(nextWidth)
    }
    const onMove = (moveEvent: ReactPointerEvent<HTMLDivElement>) => updateWidth(moveEvent.clientX)
    const onEnd = () => {
      event.currentTarget.removeEventListener('pointermove', onMove as unknown as EventListener)
      event.currentTarget.removeEventListener('pointerup', onEnd)
      event.currentTarget.removeEventListener('pointercancel', onEnd)
    }
    event.currentTarget.addEventListener('pointermove', onMove as unknown as EventListener)
    event.currentTarget.addEventListener('pointerup', onEnd)
    event.currentTarget.addEventListener('pointercancel', onEnd)
  }

  return <div className={`app ${knowledgeOpen ? 'knowledge-open' : ''} ${leftOpen ? '' : 'left-collapsed'} ${rightOpen ? '' : 'right-collapsed'}`} style={{ '--sessions-width': `${leftWidth}px`, '--context-width': `${rightWidth}px` } as CSSProperties}>
    <input ref={captureFileInput} className="visually-hidden" type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap,application/octet-stream" aria-label="选择本地报文" onChange={chooseCapture} />
    <header><button className="icon mobile-only" onClick={() => setLeftOpen(!leftOpen)} aria-label="打开会话"><Menu /></button>{!leftOpen && !knowledgeOpen && <button className="icon desktop-only" onClick={() => setLeftOpen(true)} aria-label="展开会话栏" title="展开会话栏"><PanelLeft /></button>}<div className="brand"><span className="brand-mark" role="img" aria-label="诊断助手">🦉</span><strong>PacketMaster</strong><span>TCP 诊断工作台</span></div><div className="header-actions"><span className={`connection ${health.isSuccess ? 'online' : ''}`}>{health.isSuccess ? '本机服务已连接' : '连接中断'}</span><button className="icon" onClick={refresh} title="刷新"><RefreshCw /></button><button className="command" onClick={() => setKnowledgeOpen(value => !value)}><BookOpen />{knowledgeOpen ? '诊断工作台' : '知识库'}</button>{!knowledgeOpen && <><button className="command" onClick={() => create.mutate()} disabled={create.isPending}><Plus />新建任务</button><button className="icon" onClick={() => setRightOpen(!rightOpen)} title="切换上下文栏"><PanelRight /></button></>}</div></header>
    {knowledgeOpen ? <main className="knowledge-main"><KnowledgeManagement /></main> : <><aside className="sessions"><div className="aside-head"><b>会话与任务</b><button className="icon" onClick={() => setLeftOpen(false)} aria-label="收起会话"><ChevronLeft /></button></div><div className="session-list">{sessions.data?.items.map(item => <SessionItem key={item.session_id} item={item} active={item.session_id === selected} deleting={removeSession.isPending && removeSession.variables === item.session_id} onClick={() => { setSelected(item.session_id); setPendingCapture(undefined); setTab('chat'); if (innerWidth < 800) setLeftOpen(false) }} onDelete={() => { if (window.confirm(`确定删除“${item.title}”吗？此操作无法恢复。`)) removeSession.mutate(item.session_id) }} />)}{sessions.data?.items.length === 0 && <Empty text="还没有诊断会话" />}</div></aside>{leftOpen && <div className="sidebar-resizer sidebar-resizer-left" onPointerDown={event => beginResize('left', event)} role="separator" aria-label="调整会话与任务栏宽度" aria-orientation="vertical" />}<main><nav className="tabs" aria-label="任务视图">{([['chat', MessageSquare, '对话'], ['report', FileSearch, '报告'], ['metrics', BarChart3, '指标'], ['flows', Network, 'TCP 流'], ['evidence', Activity, '证据']] as const).map(([id, Icon, label]) => <button key={id} className={tab === id ? 'active' : ''} onClick={() => setTab(id)}><Icon />{label}</button>)}</nav><div className="workspace">{!selected ? <Empty text="新建一个会话开始诊断" /> : tab === 'chat' ? <ChatView sessionId={selected} detail={detail.data} analysis={analysis.data?.analysis} pendingCapture={pendingCapture} captureUploading={attachCapture.isPending} captureError={attachCapture.error} onCapture={openCapturePicker} onClearCapture={() => setPendingCapture(undefined)} onRestoreCapture={setPendingCapture} refresh={refresh} /> : !analysisId ? <Empty text="当前会话还没有分析任务" /> : tab === 'report' ? <ReportView id={analysisId} status={analysis.data?.analysis.status} /> : tab === 'metrics' ? <MetricsView id={analysisId} status={analysis.data?.analysis.status} /> : tab === 'flows' ? <FlowsView id={analysisId} status={analysis.data?.analysis.status} /> : <EvidenceView id={analysisId} status={analysis.data?.analysis.status} />}</div></main>{rightOpen && <div className="sidebar-resizer sidebar-resizer-right" onPointerDown={event => beginResize('right', event)} role="separator" aria-label="调整当前任务栏宽度" aria-orientation="vertical" />}<aside className="context"><div className="aside-head"><b>当前任务</b><button className="icon" onClick={() => setRightOpen(false)} aria-label="收起上下文"><ChevronRight /></button></div><Context parameters={detail.data?.parameters} analysis={analysis.data?.analysis} onCapture={openCapturePicker} refresh={refresh} /></aside></>}
  </div>
}

function readSidebarWidth(key: string, fallback: number) {
  const value = Number(localStorage.getItem(key))
  return Number.isFinite(value) && value >= sidebarMinWidth ? value : fallback
}

function SessionItem({ item, active, deleting, onClick, onDelete }: { item: Session; active: boolean; deleting: boolean; onClick: () => void; onDelete: () => void }) { return <div className={`session-item ${active ? 'active' : ''}`}><button className="session-open" onClick={onClick}><span><b>{item.title}</b><small>{new Date(item.updated_at).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })}</small></span><Status value={item.status} /></button><button className="icon session-delete" onClick={onDelete} disabled={deleting} aria-label={`删除会话 ${item.title}`} title="删除会话"><Trash2 /></button></div> }
function Status({ value }: { value: TaskStatus }) { return <span className={`status status-${value}`}>{statusText[value]}</span> }
function Empty({ text }: { text: string }) { return <div className="empty"><Network /><p>{text}</p></div> }

type ChatSendInput = { content: string; draft: string; capture?: Capture }

function ChatView({ sessionId, detail, analysis, pendingCapture, captureUploading, captureError, onCapture, onClearCapture, onRestoreCapture, refresh }: { sessionId: string; detail?: SessionDetail; analysis?: Analysis; pendingCapture?: Capture; captureUploading: boolean; captureError: Error | null; onCapture: () => void; onClearCapture: () => void; onRestoreCapture: (capture: Capture | undefined) => void; refresh: () => void }) {
  const client = useQueryClient()
  const [draft, setDraft] = useState(() => localStorage.getItem(`packetmaster.draft.${sessionId}`) ?? '')
  const bottom = useRef<HTMLDivElement>(null)
  const history = useQuery({ queryKey: ['chat-history', analysis?.analysis_id], queryFn: () => api.chatHistory(analysis!.analysis_id), enabled: Boolean(analysis && isReportReady(analysis.status)) })
  const send = useMutation<ChatTurn | { parameters?: Parameters }, Error, ChatSendInput, { previous?: SessionDetail; previousHistory?: Page<ChatTurn> }>({
    mutationFn: ({ content, capture }) => analysis && isReportReady(analysis.status) ? api.chat(analysis.analysis_id, content) : api.send(sessionId, content, capture?.capture_id),
    onMutate: async ({ content, capture }) => {
      if (analysis && isReportReady(analysis.status)) {
        const historyKey = ['chat-history', analysis.analysis_id]
        await client.cancelQueries({ queryKey: historyKey })
        const previousHistory = client.getQueryData<Page<ChatTurn>>(historyKey)
        // 追问接口同样先展示问题；正式回答返回后会替换这条临时记录。
        client.setQueryData<Page<ChatTurn>>(historyKey, current => {
          const page = current ?? { items: [], total: 0, offset: 0, limit: 100 }
          return {
            ...page,
            items: [...page.items, { turn_id: `pending-${Date.now()}`, analysis_id: analysis.analysis_id, question: content, answer: '', citations: [], limitations: [], suggestions: [], created_at: new Date().toISOString() }],
            total: page.total + 1,
          }
        })
        setDraft('')
        localStorage.removeItem(`packetmaster.draft.${sessionId}`)
        return { previousHistory }
      }
      await client.cancelQueries({ queryKey: ['session', sessionId] })
      const previous = client.getQueryData<SessionDetail>(['session', sessionId])
      if (previous) {
        // 先把用户消息写入本地缓存，避免等待模型响应后才出现对话反馈。
        client.setQueryData<SessionDetail>(['session', sessionId], current => current ? {
          ...current,
          messages: {
            ...current.messages,
            items: [...current.messages.items, { message_id: `pending-${Date.now()}`, session_id: sessionId, message_type: 'user', content, created_at: new Date().toISOString(), evidence_count: 0 }],
            total: current.messages.total + 1,
          },
        } : current)
      }
      setDraft('')
      if (capture) onClearCapture()
      localStorage.removeItem(`packetmaster.draft.${sessionId}`)
      return { previous }
    },
    onError: (_error, input, context) => {
      if (analysis && isReportReady(analysis.status)) {
        client.setQueryData(['chat-history', analysis.analysis_id], context?.previousHistory)
      }
      if (context?.previous) client.setQueryData(['session', sessionId], context.previous)
      setDraft(input.draft)
      onRestoreCapture(input.capture)
    },
    onSuccess: (result) => {
      if (!analysis || !isReportReady(analysis.status) || !('turn_id' in result)) return
      client.setQueryData<Page<ChatTurn>>(['chat-history', analysis.analysis_id], current => current ? {
        ...current,
        items: current.items.map(turn => turn.turn_id.startsWith('pending-') ? result : turn),
      } : current)
    },
    onSettled: () => { refresh(); history.refetch() },
  })
  const confirm = useMutation({ mutationFn: () => api.confirm(sessionId), onSuccess: refresh })
  useEffect(() => { const key = `packetmaster.draft.${sessionId}`; if (isSensitiveDraft(draft)) localStorage.removeItem(key); else localStorage.setItem(key, draft) }, [draft, sessionId])
  useEffect(() => {
    bottom.current?.scrollIntoView?.({ block: 'end' })
  }, [detail?.messages.total, history.data?.total])
  const submit = (event: FormEvent) => {
    event.preventDefault()
    const value = draft.trim()
    if ((!value && !pendingCapture) || send.isPending) return
    send.mutate({ content: value || '请使用已附加的报文进行测速诊断', draft: value, capture: pendingCapture })
  }
  const isInitialConversation = !detail?.messages.items.length && !history.data?.items.length && !send.isPending
  return <section className={`chat-view ${isInitialConversation ? 'chat-view-initial' : ''}`}><div className="messages" aria-live="polite">{detail?.messages.items.map(message => <article key={message.message_id} className={`message message-${message.message_type}`}><p>{message.content}</p></article>)}{history.data?.items.map(turn => <article className="qa" key={turn.turn_id}><div className="question">{turn.question}</div>{turn.answer && <div className="answer"><p>{turn.answer}</p><KnowledgeReferences value={turn.knowledge_citations ?? []} compact />{turn.limitations.length > 0 && <details><summary>回答限制</summary><ul>{turn.limitations.map(item => <li key={item}>{item}</li>)}</ul></details>}</div>}</article>)}{send.isPending && <ReplyPending />}{analysis && isRunning(analysis.status) && <Progress analysis={analysis} refresh={refresh} />}{detail?.parameters?.ready_for_confirmation && !analysis && <div className="confirm-panel"><div><b>诊断参数已完整</b><span>确认后任务将在独立 Worker 中运行</span></div><ParameterGrid value={detail.parameters} /><button className="primary" onClick={() => confirm.mutate()} disabled={confirm.isPending}>{confirm.isPending ? '正在创建任务' : '开始分析'}</button></div>}{send.error && <ErrorNotice error={send.error} />}{captureError && <ErrorNotice error={captureError} />}<div ref={bottom} /></div>{isInitialConversation && <div className="conversation-welcome"><h1>你好，我是 PacketMaster</h1><p>从一段报文开始，定位链路瓶颈。</p></div>}<form onSubmit={submit}>{pendingCapture && <div className="capture-attachment"><FileSearch /><span><b>{pendingCapture.file_name}</b><small>{formatBytes(pendingCapture.size_bytes)}</small></span><button type="button" className="icon" onClick={onClearCapture} aria-label="移除报文附件"><X /></button></div>}<div className="composer"><button type="button" className="icon" onClick={onCapture} disabled={captureUploading} title="选择报文文件"><Plus /></button><textarea value={draft} onChange={event => setDraft(event.target.value.slice(0, 2000))} onKeyDown={event => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); event.currentTarget.form?.requestSubmit() } }} placeholder="有问题，尽管问" aria-label="对话输入" /><span className="counter">{draft.length}/2000</span><button className="icon send" type="submit" disabled={(!draft.trim() && !pendingCapture) || send.isPending} title="发送"><Send /></button></div></form></section>
}

function ReplyPending() {
  const [index, setIndex] = useState(0)
  useEffect(() => {
    const timer = window.setInterval(() => setIndex(value => (value + 1) % replyStatusLabels.length), 1_400)
    return () => window.clearInterval(timer)
  }, [])
  return <article className="message message-pending" aria-label="正在等待模型回复"><p><RefreshCw />{replyStatusLabels[index]}</p></article>
}

function Progress({ analysis, refresh }: { analysis: Analysis; refresh: () => void }) {
  const cancel = useMutation({ mutationFn: () => api.cancel(analysis.analysis_id), onSuccess: refresh })
  const requestCancel = () => {
    if (window.confirm('确定要取消当前分析任务吗？已完成的本地产物会保留。')) cancel.mutate()
  }
  return <div className="progress-block"><div className="progress-head"><Status value={analysis.status} /><span>{analysis.stage_message || '任务处理中'}</span><button className="icon danger" onClick={requestCancel} disabled={cancel.isPending} title="取消分析"><Square /></button></div><div className="progress-track"><i style={{ width: `${Math.round((analysis.progress_fraction ?? 0.08) * 100)}%` }} /></div><div className="progress-meta"><span>{analysis.processed_packets ? `已处理 ${analysis.processed_packets.toLocaleString()} 个报文` : '正在准备分析数据'}</span><span>{analysis.elapsed_seconds.toFixed(1)} 秒</span></div></div>
}

function Context({ parameters, analysis, onCapture, refresh }: { parameters?: Parameters; analysis?: Analysis; onCapture: () => void; refresh: () => void }) {
  const retry = useMutation({ mutationFn: () => api.retry(analysis!.analysis_id), onSuccess: refresh })
  const value = parameters ?? (analysis ? { capture: analysis.capture, standard_bandwidth_mbps: analysis.standard_bandwidth_mbps, actual_bandwidth_mbps: analysis.actual_bandwidth_mbps, target: analysis.target, missing: [], assumptions: [], ambiguities: [], ready_for_confirmation: false } : undefined)
  return <div className="context-body">{analysis && <section className="context-section"><label>任务状态</label><div className="context-status"><Status value={analysis.status} /><span>{analysis.stage_message}</span></div></section>}<section className="context-section"><label>报文文件</label>{value?.capture ? <div className="file-row"><FileSearch /><span><b>{value.capture.file_name}</b><small>{formatBytes(value.capture.size_bytes)}</small></span></div> : <button className="secondary full" onClick={onCapture}><FileUp />加载报文</button>}</section>{value && <><section className="context-section"><label>测速参数</label><ParameterGrid value={value} /></section><section className="context-section"><label>分析方向</label><b>{targetText[value.target]}</b><small>未明确指定时默认分析下载方向</small></section></>}{analysis && ['failed', 'cancelled', 'interrupted', 'partial'].includes(analysis.status) && <button className="secondary full" onClick={() => retry.mutate()} disabled={retry.isPending}><RefreshCw />重试任务</button>}</div>
}

function ParameterGrid({ value }: { value: Parameters }) { return <div className="parameter-grid"><span>标准带宽<b>{value.standard_bandwidth_mbps ? `${value.standard_bandwidth_mbps} Mbps` : '待补充'}</b></span><span>实际带宽<b>{value.actual_bandwidth_mbps ? `${value.actual_bandwidth_mbps} Mbps` : '待补充'}</b></span><span>分析方向<b>{targetText[value.target]}</b></span></div> }

function ReportView({ id, status }: { id: string; status?: TaskStatus }) {
  const query = useQuery({ queryKey: ['report', id], queryFn: () => api.report(id), enabled: isReportReady(status) })
  if (!isReportReady(status)) return <Empty text="报告将在分析完成后生成" />
  if (query.isLoading) return <Loading />
  if (query.error) return <ErrorNotice error={query.error} />
  const report = query.data!.report
  const complete = Boolean(report.coverage_summary.complete)
  const truncated = Boolean(report.coverage_summary.truncated)
  return <section className="report-view">
    <div className="report-summary"><Metric label="标准带宽" value={`${report.standard_bandwidth_mbps} Mbps`} /><Metric label="实际带宽" value={`${report.actual_bandwidth_mbps} Mbps`} /><Metric label="达标率" value={`${report.achievement_ratio_pct.toFixed(1)}%`} tone={report.achievement_ratio_pct < 80 ? 'warn' : 'good'} /><Metric label="置信度" value={`${report.confidence.toFixed(0)}%`} /></div>
    <section className="cause-band"><label>主要原因</label><h2>{report.primary_cause}</h2><span>{targetText[report.target]}方向 · {complete ? '覆盖完整' : '覆盖不完整'}{truncated ? ' · 数据已截断' : ''}</span></section>
    <Section title={`候选原因 ${report.candidate_causes.length}`}><div className="cause-list">{report.candidate_causes.map((cause, index) => <details key={index} open={index === 0}><summary><b>{String(cause.cause ?? `候选原因 ${index + 1}`)}</b><span>{String(cause.confidence ?? 0)}% 置信度</span></summary><div className="cause-body"><p>{String(cause.explanation ?? '')}</p><EvidenceList label="支持证据" value={cause.supporting_evidence} /><EvidenceList label="反向证据" value={cause.contradicting_evidence} /><EvidenceList label="缺失证据" value={cause.missing_evidence} />{Boolean(cause.suggestion) && <p><b>排查建议：</b>{String(cause.suggestion)}</p>}</div></details>)}</div></Section>
    <KnowledgeReferences value={report.knowledge_citations ?? []} />
    <div className="report-columns"><Section title="限制条件"><StringList value={report.limitations} empty="未记录限制" /></Section><Section title="排查步骤"><StringList value={report.troubleshooting_steps} empty="暂无步骤" /></Section><Section title="优化建议"><StringList value={report.optimization_suggestions} empty="暂无建议" /></Section></div>
  </section>
}

function MetricsView({ id, status }: { id: string; status?: TaskStatus }) {
  const query = useQuery({ queryKey: ['metrics', id], queryFn: () => api.metrics(id), enabled: isReportReady(status) })
  const metrics = query.data
  const throughput = useMemo(() => throughputOption(metrics), [metrics])
  const rtt = useMemo(() => rttOption(metrics), [metrics])
  const events = useMemo(() => eventOption(metrics), [metrics])
  if (!isReportReady(status)) return <Empty text="指标将在分析完成后生成" />
  if (query.isLoading) return <Loading />
  if (query.error) return <ErrorNotice error={query.error} />
  return <section className="metrics-view"><div className="metric-strip"><Metric label="TCP 报文" value={number(metrics?.tcp_summary.packet_count)} /><Metric label="重传" value={number(metrics?.tcp_summary.retransmission_count)} tone="warn" /><Metric label="重复 ACK" value={number(metrics?.tcp_summary.duplicate_ack_count)} /><Metric label="零窗口" value={number(metrics?.tcp_summary.zero_window_count)} /></div>{metrics?.downsampled && <div className="notice">时间序列已降采样至 {metrics.point_limit} 个数据点，异常事件仍保留。</div>}<Suspense fallback={<Loading />}><div className="chart-grid"><Chart option={throughput} label="吞吐量时间序列" /><Chart option={rtt} label="RTT 分布" /><Chart option={events} label="TCP 异常事件时间线" /></div></Suspense></section>
}

function FlowsView({ id, status }: { id: string; status?: TaskStatus }) {
  const [offset, setOffset] = useState(0)
  const [direction, setDirection] = useState('')
  const query = useQuery({ queryKey: ['flows', id, offset, direction], queryFn: () => api.flows(id, offset, direction), enabled: isReportReady(status) })
  if (!isReportReady(status)) return <Empty text="TCP 流将在分析完成后可用" />
  return <section className="table-view"><div className="view-toolbar"><div><h2>TCP 流</h2><span>{query.data?.total ?? 0} 条完整流记录</span></div><select value={direction} onChange={event => { setDirection(event.target.value); setOffset(0) }} aria-label="流方向"><option value="">全部方向</option><option value="download">下载</option><option value="upload">上行</option></select></div>{query.isLoading ? <Loading /> : query.error ? <ErrorNotice error={query.error} /> : <><div className="table-scroll"><table><thead><tr><th>流 ID</th><th>方向</th><th>吞吐 Mbps</th><th>报文</th><th>载荷字节</th><th>重传</th><th>重复 ACK</th><th>窗口范围</th></tr></thead><tbody>{query.data?.items.map(flow => <tr key={flow.flow_id}><td className="flow-id">{flow.flow_id}</td><td>{targetText[flow.direction]}</td><td>{flow.throughput_mbps.toFixed(2)}</td><td>{flow.packet_count.toLocaleString()}</td><td>{flow.payload_bytes.toLocaleString()}</td><td>{flow.retransmission_count}</td><td>{flow.duplicate_ack_count}</td><td>{flow.window_min ?? '-'} – {flow.window_max ?? '-'}</td></tr>)}</tbody></table></div><Pager offset={offset} total={query.data?.total ?? 0} limit={50} setOffset={setOffset} /></>}</section>
}

function EvidenceView({ id, status }: { id: string; status?: TaskStatus }) {
  const [offset, setOffset] = useState(0)
  const [type, setType] = useState('retransmission')
  const [flow, setFlow] = useState('')
  const query = useQuery({ queryKey: ['evidence', id, type, offset, flow], queryFn: () => api.evidence(id, type, offset, flow), enabled: isReportReady(status) })
  if (!isReportReady(status)) return <Empty text="证据将在分析完成后可用" />
  return <section className="table-view"><div className="view-toolbar"><div><h2>证据浏览</h2><span>仅展示允许的 TCP 字段，不包含 Payload</span></div><div className="filters"><select value={type} onChange={event => { setType(event.target.value); setOffset(0) }} aria-label="证据类型">{['retransmission', 'duplicate_ack', 'out_of_order', 'zero_window', 'window_full', 'packet_fields', 'summary'].map(item => <option key={item}>{item}</option>)}</select><input value={flow} onChange={event => setFlow(event.target.value)} placeholder="按流 ID 筛选" aria-label="流 ID" /></div></div>{query.isLoading ? <Loading /> : query.error ? <ErrorNotice error={query.error} /> : <EvidenceTable evidence={query.data!} />}<Pager offset={offset} total={query.data?.total ?? 0} limit={50} setOffset={setOffset} /></section>
}

function EvidenceTable({ evidence }: { evidence: Evidence }) { const keys = Array.from(new Set(evidence.items.flatMap(item => Object.keys(item)))); return evidence.items.length === 0 ? <Empty text="当前筛选条件没有证据" /> : <div className="table-scroll"><table><thead><tr>{keys.map(key => <th key={key}>{key}</th>)}</tr></thead><tbody>{evidence.items.map((item, index) => <tr key={String(item.evidence_id ?? index)}>{keys.map(key => <td key={key}>{String(item[key] ?? '-')}</td>)}</tr>)}</tbody></table></div> }
function Pager({ offset, total, limit, setOffset }: { offset: number; total: number; limit: number; setOffset: (value: number) => void }) { return <div className="pager"><button className="secondary" onClick={() => setOffset(Math.max(0, offset - limit))} disabled={offset === 0}><ChevronLeft />上一页</button><span>{total === 0 ? 0 : offset + 1}–{Math.min(offset + limit, total)} / {total}</span><button className="secondary" onClick={() => setOffset(offset + limit)} disabled={offset + limit >= total}>下一页<ChevronRight /></button></div> }

function Section({ title, children }: { title: string; children: React.ReactNode }) { return <section className="report-section"><h3>{title}</h3>{children}</section> }
function Metric({ label, value, tone = '' }: { label: string; value: string; tone?: string }) { return <div className={`metric ${tone}`}><label>{label}</label><b>{value}</b></div> }
function StringList({ value, empty }: { value: string[]; empty: string }) { return value.length ? <ol>{value.map(item => <li key={item}>{item}</li>)}</ol> : <p className="muted">{empty}</p> }
function EvidenceList({ label, value }: { label: string; value: unknown }) { return Array.isArray(value) && value.length ? <div><b>{label}</b><ul>{value.map(item => <li key={String(item)}>{String(item)}</li>)}</ul></div> : null }
export function KnowledgeReferences({ value, compact = false }: { value: KnowledgeCitation[]; compact?: boolean }) { return value.length ? <section className={`knowledge-references ${compact ? 'compact' : ''}`} aria-label="知识经验引用"><h3>知识经验引用</h3>{value.map(item => <details key={`${item.version_id}:${item.chunk_id}`}><summary><b>{item.title}</b><span>{item.knowledge_type} · {item.source_name}</span></summary><div><p>{item.supported_statement}</p><blockquote>{item.supporting_quote}</blockquote><small>版本 {item.version_id}{item.source_location ? ` · ${item.source_location}` : ''}</small></div></details>)}</section> : null }
function Loading() { return <div className="loading"><RefreshCw />正在读取任务数据</div> }
function ErrorNotice({ error }: { error: Error }) { const failure = error as ApiFailure; return <div className="error-notice" role="alert"><b>{failure.message}</b>{failure.action && <span>{failure.action}</span>}</div> }
const number = (value?: number) => (value ?? 0).toLocaleString()
const isSensitiveDraft = (value: string) => /sk-[a-z0-9_-]{12,}|(?:[a-z]:[\\/]|\/users\/|\/home\/|\/private\/|\/tmp\/)/i.test(value)

function throughputOption(metrics?: Metrics): EChartsOption { return { title: { text: '吞吐量时间序列', textStyle: { fontSize: 14 } }, tooltip: { trigger: 'axis' }, grid: { left: 48, right: 18, top: 48, bottom: 36 }, xAxis: { type: 'category', name: '秒', data: metrics?.intervals.map(item => String(item.interval_start)) ?? [] }, yAxis: { type: 'value', name: 'Mbps' }, series: [{ type: 'line', symbol: 'none', data: metrics?.intervals.map(item => Number(item.throughput_mbps ?? 0)) ?? [], lineStyle: { color: '#176b87', width: 2 }, areaStyle: { color: 'rgba(23,107,135,.12)' } }] } }
function rttOption(metrics?: Metrics): EChartsOption { return { title: { text: 'RTT 分布', textStyle: { fontSize: 14 } }, tooltip: {}, grid: { left: 48, right: 18, top: 48, bottom: 36 }, xAxis: { type: 'category', data: metrics?.rtt_histogram.map(item => item.upper_bound_ms === 'inf' ? '∞' : `≤${item.upper_bound_ms}`) ?? [] }, yAxis: { type: 'value', name: '报文数' }, series: [{ type: 'bar', data: metrics?.rtt_histogram.map(item => item.count) ?? [], itemStyle: { color: '#3f7d58' } }] } }
function eventOption(metrics?: Metrics): EChartsOption { const names = ['retransmission_count', 'duplicate_ack_count', 'out_of_order_count', 'zero_window_count', 'window_full_count']; return { title: { text: 'TCP 事件', textStyle: { fontSize: 14 } }, tooltip: { trigger: 'axis' }, grid: { left: 48, right: 18, top: 48, bottom: 58 }, xAxis: { type: 'category', axisLabel: { rotate: 25 }, data: names.map(name => name.replace('_count', '')) }, yAxis: { type: 'value' }, series: [{ type: 'bar', data: names.map(name => metrics?.tcp_summary[name] ?? 0), itemStyle: { color: '#b75d36' } }] } }

function useAnalysisEvents(id: string | undefined, client: ReturnType<typeof useQueryClient>) {
  // SSE 只用于刷新查询缓存；页面状态始终以服务端持久化记录为准。
  useEffect(() => {
    if (!id) return
    const key = `packetmaster.event.${id}`
    const after = sessionStorage.getItem(key) ?? '0'
    const source = new EventSource(`/api/analyses/${id}/events?after_event_id=${after}`)
    const update = (event: MessageEvent) => { if (event.lastEventId) sessionStorage.setItem(key, event.lastEventId); client.invalidateQueries({ queryKey: ['analysis', id] }); client.invalidateQueries({ queryKey: ['sessions'] }); client.invalidateQueries({ queryKey: ['session'] }) }
    ;['analysis_status', 'analysis_progress', 'analysis_completed', 'analysis_partial', 'analysis_failed', 'analysis_cancelled'].forEach(name => source.addEventListener(name, update))
    return () => source.close()
  }, [id, client])
}
