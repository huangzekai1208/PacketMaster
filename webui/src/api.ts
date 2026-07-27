export type TaskStatus = 'draft' | 'awaiting_confirmation' | 'queued' | 'validating' | 'analyzing' | 'reasoning' | 'verifying' | 'reporting' | 'completed' | 'partial' | 'failed' | 'cancelled' | 'interrupted'
export type Target = 'download' | 'upload' | 'both'

export interface Session { session_id: string; title: string; status: TaskStatus; current_analysis_id?: string; created_at: string; updated_at: string }
export interface Capture { capture_id: string; file_name: string; size_bytes: number }
export interface Message { message_id: string; session_id: string; message_type: string; content: string; created_at: string; analysis_id?: string; evidence_count: number }
export interface Parameters { capture?: Capture; standard_bandwidth_mbps?: number; actual_bandwidth_mbps?: number; target: Target; missing: string[]; assumptions: string[]; ambiguities: string[]; ready_for_confirmation: boolean }
export interface Analysis { analysis_id: string; session_id: string; status: TaskStatus; stage_message: string; progress_fraction?: number; capture: Capture; standard_bandwidth_mbps: number; actual_bandwidth_mbps: number; target: Target; created_at: string; updated_at: string; elapsed_seconds: number; processed_packets?: number; error_code?: string }
export interface SessionDetail { session: Session; messages: Page<Message>; parameters?: Parameters }
export interface Page<T> { items: T[]; total: number; offset: number; limit: number }
export interface KnowledgeCitation { knowledge_id: string; version_id: string; chunk_id: string; title: string; knowledge_type: string; source_name: string; source_location?: string; supported_statement: string; supporting_quote: string; applicability_note?: string }
export interface Report { standard_bandwidth_mbps: number; actual_bandwidth_mbps: number; achievement_ratio_pct: number; target: Target; primary_cause: string; candidate_causes: Array<Record<string, unknown>>; key_evidence: Array<Record<string, unknown>>; confidence: number; coverage_summary: Record<string, unknown>; evidence_quality: Record<string, unknown>; limitations: string[]; troubleshooting_steps: string[]; optimization_suggestions: string[]; knowledge_citations?: KnowledgeCitation[]; knowledge_conflicts?: Array<Record<string, unknown>>; analysis_metadata: Record<string, unknown> }
export interface Metrics { tcp_summary: Record<string, number>; coverage_summary: Record<string, unknown>; intervals: Array<Record<string, number | string>>; rtt_histogram: Array<{ upper_bound_ms: number | string; count: number }>; top_flows: Flow[]; point_limit: number; downsampled: boolean }
export interface Flow { flow_id: string; direction: Target; packet_count: number; payload_bytes: number; throughput_mbps: number; duration_seconds: number; retransmission_count: number; duplicate_ack_count: number; out_of_order_count: number; zero_window_count: number; window_full_count: number; window_min?: number; window_max?: number }
export interface Evidence { analysis_id: string; evidence_type: string; items: Array<Record<string, string | number | boolean>>; total: number; next_offset?: number; truncated: boolean; warnings: string[] }
export interface ChatTurn { turn_id: string; analysis_id: string; question: string; answer: string; citations: Array<Record<string, unknown>>; knowledge_citations?: KnowledgeCitation[]; limitations: string[]; suggestions: string[]; created_at: string }

interface Envelope<T> { ok: true; data: T }
interface ErrorEnvelope { ok: false; error: { code: string; message: string; suggested_action: string; recoverable: boolean } }

export class ApiFailure extends Error { constructor(public code: string, message: string, public action = '') { super(message) } }

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { ...init, headers: { 'Content-Type': 'application/json', ...init?.headers } })
  const body = await response.json() as Envelope<T> | ErrorEnvelope
  if (!response.ok || !body.ok) {
    const error = (body as ErrorEnvelope).error
    throw new ApiFailure(error?.code ?? 'REQUEST_FAILED', error?.message ?? '请求失败', error?.suggested_action)
  }
  return body.data
}

export const api = {
  health: () => request<{ status: string; model_configured: boolean; tshark_configured: boolean }>('/api/health'),
  sessions: () => request<Page<Session>>('/api/sessions?limit=50'),
  createSession: () => request<Session>('/api/sessions', { method: 'POST', body: '{}' }),
  session: (id: string) => request<SessionDetail>(`/api/sessions/${id}`),
  send: (id: string, content: string, capture_id?: string) => request<{ parameters?: Parameters }>(`/api/sessions/${id}/messages`, { method: 'POST', body: JSON.stringify({ content, capture_id }) }),
  register: (path: string) => request<Capture>('/api/captures/register', { method: 'POST', body: JSON.stringify({ path }) }),
  recent: () => request<Capture[]>('/api/captures/recent'),
  confirm: (id: string) => request<Analysis>(`/api/sessions/${id}/confirm`, { method: 'POST', body: '{}' }),
  analysis: (id: string) => request<{ analysis: Analysis; report_available: boolean; recoverable: boolean; suggested_action: string }>(`/api/analyses/${id}`),
  cancel: (id: string) => request<Analysis>(`/api/analyses/${id}/cancel`, { method: 'POST' }),
  retry: (id: string) => request<Analysis>(`/api/analyses/${id}/retry`, { method: 'POST' }),
  report: (id: string) => request<{ analysis_id: string; report: Report }>(`/api/analyses/${id}/report`),
  metrics: (id: string) => request<Metrics>(`/api/analyses/${id}/metrics`),
  flows: (id: string, offset: number, direction = '') => request<Page<Flow>>(`/api/analyses/${id}/flows?offset=${offset}&limit=50${direction ? `&direction=${direction}` : ''}`),
  evidence: (id: string, type: string, offset: number, flow = '') => request<Evidence>(`/api/analyses/${id}/evidence?evidence_type=${type}&offset=${offset}&limit=50${flow ? `&flow_id=${encodeURIComponent(flow)}` : ''}`),
  chat: (id: string, question: string) => request<ChatTurn>(`/api/analyses/${id}/chat`, { method: 'POST', body: JSON.stringify({ question }) }),
  chatHistory: (id: string) => request<Page<ChatTurn>>(`/api/analyses/${id}/chat`),
}

export const isRunning = (status?: TaskStatus) => Boolean(status && ['queued', 'validating', 'analyzing', 'reasoning', 'verifying', 'reporting'].includes(status))
export const isReportReady = (status?: TaskStatus) => status === 'completed' || status === 'partial'
export const formatBytes = (bytes = 0) => bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} KB` : bytes < 1024 ** 3 ? `${(bytes / 1024 ** 2).toFixed(1)} MB` : `${(bytes / 1024 ** 3).toFixed(2)} GB`
