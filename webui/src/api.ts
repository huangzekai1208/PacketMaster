// Web API 客户端：仅使用公开 ID 和元数据，绝不向界面泄露服务端本地路径。
export type TaskStatus = 'draft' | 'awaiting_confirmation' | 'queued' | 'validating' | 'analyzing' | 'reasoning' | 'verifying' | 'reporting' | 'completed' | 'partial' | 'failed' | 'cancelled' | 'interrupted'
export type Target = 'download' | 'upload' | 'both'
export type AnalysisMode = 'speed' | 'stall'

export interface Session { session_id: string; title: string; status: TaskStatus; current_analysis_id?: string; created_at: string; updated_at: string }
export interface Capture { capture_id: string; file_name: string; size_bytes: number }
export interface RagMessageCitation { knowledge_id: string; title: string; chunk_id: string; reranker_score?: number }
export interface Message { message_id: string; session_id: string; message_type: string; content: string; created_at: string; analysis_id?: string; evidence_count: number; rag_status?: 'used' | 'degraded'; rag_reason?: string; rag_citations?: RagMessageCitation[] }
export interface Parameters { capture?: Capture; mode: AnalysisMode; standard_bandwidth_mbps?: number; actual_bandwidth_mbps?: number; target: Target; missing: string[]; assumptions: string[]; ambiguities: string[]; ready_for_confirmation: boolean }
export interface Analysis { analysis_id: string; session_id: string; status: TaskStatus; stage_message: string; progress_fraction?: number; capture: Capture; mode: AnalysisMode; standard_bandwidth_mbps: number; actual_bandwidth_mbps: number; target: Target; created_at: string; updated_at: string; elapsed_seconds: number; processed_packets?: number; error_code?: string }
export interface AnalysisDetail { analysis: Analysis; report_available: boolean; recoverable: boolean; error_message: string; suggested_action: string; error_details: Record<string, string | number | boolean | null> }
export interface SessionDetail { session: Session; messages: Page<Message>; parameters?: Parameters }
export interface Page<T> { items: T[]; total: number; offset: number; limit: number }
export interface KnowledgeCitation { knowledge_id: string; version_id: string; chunk_id: string; title: string; knowledge_type: string; source_name: string; source_location?: string; supported_statement: string; supporting_quote: string; applicability_note?: string }
export interface SpeedReport { mode?: 'speed'; standard_bandwidth_mbps: number; actual_bandwidth_mbps: number; achievement_ratio_pct: number; target: Target; primary_cause: string; candidate_causes: Array<Record<string, unknown>>; key_evidence: Array<Record<string, unknown>>; confidence: number; coverage_summary: Record<string, unknown>; evidence_quality: Record<string, unknown>; limitations: string[]; troubleshooting_steps: string[]; optimization_suggestions: string[]; knowledge_citations?: KnowledgeCitation[]; knowledge_conflicts?: Array<Record<string, unknown>>; analysis_metadata: Record<string, unknown> }
export interface StallReport { mode: 'stall'; analysis_id: string; primary_cause: string; candidate_causes: Array<Record<string, unknown>>; key_evidence: Array<Record<string, unknown>>; confidence: number; coverage_summary: Record<string, unknown>; stall_events: Array<Record<string, unknown>>; protocol_summary: Record<string, unknown>; endpoint_summary: Array<Record<string, unknown>>; dns_summary: Record<string, unknown>; tls_summary: Record<string, unknown>; http_summary: Record<string, unknown>; udp_summary: Record<string, unknown>; keyword_summary: Record<string, number>; limitations: string[]; troubleshooting_steps: string[]; optimization_suggestions: string[]; analysis_metadata: Record<string, unknown> }
export type Report = SpeedReport | StallReport
export interface Metrics { tcp_summary: Record<string, number>; coverage_summary: Record<string, unknown>; intervals: Array<Record<string, number | string>>; rtt_histogram: Array<{ upper_bound_ms: number | string; count: number }>; top_flows: Flow[]; point_limit: number; downsampled: boolean }
export interface Flow { flow_id: string; direction: Target; packet_count: number; payload_bytes: number; throughput_mbps: number; duration_seconds: number; retransmission_count: number; duplicate_ack_count: number; out_of_order_count: number; zero_window_count: number; window_full_count: number; window_min?: number; window_max?: number }
export interface Evidence { analysis_id: string; evidence_type: string; items: Array<Record<string, string | number | boolean>>; total: number; next_offset?: number; truncated: boolean; warnings: string[] }
export interface ChatTurn { turn_id: string; analysis_id: string; question: string; answer: string; citations: Array<Record<string, unknown>>; knowledge_citations?: KnowledgeCitation[]; limitations: string[]; suggestions: string[]; created_at: string }
export type KnowledgeStatus = 'draft' | 'approved' | 'disabled' | 'superseded'
export type KnowledgeType = 'standard' | 'vendor' | 'runbook' | 'case'
export type AuthorityLevel = 'high' | 'medium_high' | 'medium' | 'low'
export interface KnowledgeSummary { knowledge_id: string; title: string; knowledge_type: KnowledgeType; authority: AuthorityLevel; status: KnowledgeStatus; language: string; summary: string; current_version_id?: string }
export interface KnowledgeVersion { version_id: string; version_number: number; source_name: string; source_location: string; status: KnowledgeStatus; created_at: string; approved_at?: string; approved_by?: string; chunk_count: number }
export interface KnowledgeDetail { document: KnowledgeSummary; versions: KnowledgeVersion[] }
export interface KnowledgeImportRequest { file_name: string; content: string; knowledge_id: string; title: string; knowledge_type: KnowledgeType; authority: AuthorityLevel; source_name: string; source_location: string; language: string; summary: string; version: number; ack_risk: boolean }
export interface KnowledgePreview { knowledge_id: string; version_id: string; chunk_count: number; risk_flags: string[]; warnings: string[]; requires_risk_acknowledgement: boolean; chunks: Array<{ chunk_id: string; heading_path: string[]; content: string }> }
export interface KnowledgeMutation { version_id: string; indexed_chunks: number; status?: KnowledgeStatus }
export interface KnowledgeEvaluationStatus { active_gate_passed: boolean; requested_mode: string; effective_mode: string; last_report?: Record<string, number | boolean> }
export interface LLMUsageSummary { call_count: number; succeeded_count: number; failed_count: number; retry_count: number; calls_with_token_usage: number; input_tokens: number; output_tokens: number; total_tokens: number; estimated_cost_usd: number; operation_counts: Record<string, number> }

interface Envelope<T> { ok: true; data: T }
interface ErrorEnvelope { ok: false; error: { code: string; message: string; suggested_action: string; recoverable: boolean } }

export class ApiFailure extends Error { constructor(public code: string, message: string, public action = '') { super(message) } }

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  // JSON API 统一解包稳定错误信封，调用方只处理 ApiFailure。
  const response = await fetch(path, { ...init, headers: { 'Content-Type': 'application/json', ...init?.headers } })
  const body = await response.json() as Envelope<T> | ErrorEnvelope
  if (!response.ok || !body.ok) {
    const error = (body as ErrorEnvelope).error
    throw new ApiFailure(error?.code ?? 'REQUEST_FAILED', error?.message ?? '请求失败', error?.suggested_action)
  }
  return body.data
}

export const api = {
  health: () => request<{ status: string; model_configured: boolean; model_cost_configured: boolean; tshark_configured: boolean }>('/api/health'),
  llmUsage: () => request<LLMUsageSummary>('/api/llm-observability/summary?limit=10000'),
  sessions: () => request<Page<Session>>('/api/sessions?limit=50'),
  createSession: () => request<Session>('/api/sessions', { method: 'POST', body: '{}' }),
  deleteSession: (id: string) => request<{ deleted: boolean }>(`/api/sessions/${id}`, { method: 'DELETE' }),
  session: (id: string) => request<SessionDetail>(`/api/sessions/${id}`),
  send: (id: string, content: string, capture_id?: string, mode: AnalysisMode = 'speed') => request<{ parameters?: Parameters }>(`/api/sessions/${id}/messages`, { method: 'POST', body: JSON.stringify({ content, capture_id, mode }) }),
  register: (path: string) => request<Capture>('/api/captures/register', { method: 'POST', body: JSON.stringify({ path }) }),
  uploadCapture: async (file: File) => {
    // 上传使用 multipart，不能附带默认 JSON Content-Type，否则浏览器不会生成 boundary。
    const body = new FormData()
    body.append('file', file)
    const response = await fetch('/api/captures/upload', { method: 'POST', body })
    const payload = await response.json() as Envelope<Capture> | ErrorEnvelope
    if (!response.ok || !payload.ok) {
      const error = (payload as ErrorEnvelope).error
      throw new ApiFailure(error?.code ?? 'REQUEST_FAILED', error?.message ?? '请求失败', error?.suggested_action)
    }
    return payload.data
  },
  recent: () => request<Capture[]>('/api/captures/recent'),
  confirm: (id: string) => request<Analysis>(`/api/sessions/${id}/confirm`, { method: 'POST', body: '{}' }),
  analysis: (id: string) => request<AnalysisDetail>(`/api/analyses/${id}`),
  cancel: (id: string) => request<Analysis>(`/api/analyses/${id}/cancel`, { method: 'POST' }),
  retry: (id: string) => request<Analysis>(`/api/analyses/${id}/retry`, { method: 'POST' }),
  report: (id: string) => request<{ analysis_id: string; report: Report }>(`/api/analyses/${id}/report`),
  metrics: (id: string) => request<Metrics>(`/api/analyses/${id}/metrics`),
  flows: (id: string, offset: number, direction = '') => request<Page<Flow>>(`/api/analyses/${id}/flows?offset=${offset}&limit=50${direction ? `&direction=${direction}` : ''}`),
  evidence: (id: string, type: string, offset: number, flow = '') => request<Evidence>(`/api/analyses/${id}/evidence?evidence_type=${type}&offset=${offset}&limit=50${flow ? `&flow_id=${encodeURIComponent(flow)}` : ''}`),
  chat: (id: string, question: string) => request<ChatTurn>(`/api/analyses/${id}/chat`, { method: 'POST', body: JSON.stringify({ question }) }),
  chatHistory: (id: string) => request<Page<ChatTurn>>(`/api/analyses/${id}/chat`),
  knowledge: (status = '') => request<Page<KnowledgeSummary>>(`/api/knowledge?limit=100${status ? `&status=${status}` : ''}`),
  knowledgeDetail: (id: string) => request<KnowledgeDetail>(`/api/knowledge/${id}`),
  previewKnowledge: (body: KnowledgeImportRequest) => request<KnowledgePreview>('/api/knowledge/preview', { method: 'POST', body: JSON.stringify(body) }),
  importKnowledge: (body: KnowledgeImportRequest) => request<KnowledgeMutation>('/api/knowledge/import', { method: 'POST', body: JSON.stringify(body) }),
  approveKnowledge: (id: string, reviewer: string) => request<KnowledgeMutation>(`/api/knowledge/versions/${id}/approve`, { method: 'POST', body: JSON.stringify({ reviewer }) }),
  disableKnowledge: (id: string, actor: string, reason: string) => request<KnowledgeMutation>(`/api/knowledge/versions/${id}/disable`, { method: 'POST', body: JSON.stringify({ actor, reason }) }),
  reindexKnowledge: (id: string, force: boolean) => request<KnowledgeMutation>(`/api/knowledge/versions/${id}/reindex`, { method: 'POST', body: JSON.stringify({ force }) }),
  knowledgeEvaluation: () => request<KnowledgeEvaluationStatus>('/api/knowledge/evaluation-status'),
}

export const isRunning = (status?: TaskStatus) => Boolean(status && ['queued', 'validating', 'analyzing', 'reasoning', 'verifying', 'reporting'].includes(status))
export const isReportReady = (status?: TaskStatus) => status === 'completed' || status === 'partial'
export const formatBytes = (bytes = 0) => bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} KB` : bytes < 1024 ** 3 ? `${(bytes / 1024 ** 2).toFixed(1)} MB` : `${(bytes / 1024 ** 3).toFixed(2)} GB`
