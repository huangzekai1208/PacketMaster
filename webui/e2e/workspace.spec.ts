import { expect, Page, test } from '@playwright/test'

const now = '2026-07-26T12:00:00Z'
const capture = {
  capture_id: 'capture_demo',
  file_name: 'download-underperform.pcapng',
  size_bytes: 734003200,
}
const session = {
  session_id: 'session_demo',
  title: '下载测速不达标诊断',
  status: 'completed',
  current_analysis_id: 'analysis_demo',
  created_at: now,
  updated_at: now,
}
const analysis = {
  analysis_id: 'analysis_demo',
  session_id: 'session_demo',
  status: 'completed',
  stage_message: '诊断报告已生成',
  capture,
  standard_bandwidth_mbps: 1000,
  actual_bandwidth_mbps: 20,
  target: 'download',
  created_at: now,
  updated_at: now,
  elapsed_seconds: 18.4,
  processed_packets: 284392,
}

const ok = (data: unknown) => JSON.stringify({ ok: true, data, request_id: 'playwright' })

async function mockApi(
  page: Page,
  initialStatus: 'awaiting_confirmation' | 'analyzing' | 'completed' | 'failed' = 'completed',
) {
  let currentStatus = initialStatus
  let hasAnalysis = initialStatus !== 'awaiting_confirmation'
  const actions: string[] = []
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url())
    if (url.pathname.endsWith('/events')) {
      await route.fulfill({
        status: 200,
        contentType: 'text/event-stream',
        body: 'event: heartbeat\ndata: {}\n\n',
      })
      return
    }

    let data: unknown
    const currentSession = {
      ...session,
      status: currentStatus,
      current_analysis_id: hasAnalysis ? 'analysis_demo' : undefined,
    }
    const currentAnalysis = {
      ...analysis,
      status: currentStatus,
      stage_message: currentStatus === 'failed' ? '模型调用失败' : '正在分析 TCP 报文',
    }
    if (url.pathname === '/api/health') {
      data = { status: 'ok', model_configured: true, tshark_configured: true }
    } else if (url.pathname === '/api/sessions') {
      data = { items: [currentSession], total: 1, offset: 0, limit: 50 }
    } else if (url.pathname === '/api/sessions/session_demo/confirm') {
      actions.push('confirm')
      hasAnalysis = true
      currentStatus = 'analyzing'
      data = { ...currentAnalysis, status: currentStatus }
    } else if (url.pathname.endsWith('/cancel')) {
      actions.push('cancel')
      currentStatus = 'cancelled'
      data = { ...currentAnalysis, status: currentStatus }
    } else if (url.pathname.endsWith('/retry')) {
      actions.push('retry')
      currentStatus = 'analyzing'
      data = { ...currentAnalysis, status: currentStatus }
    } else if (url.pathname === '/api/sessions/session_demo') {
      data = {
        session: currentSession,
        messages: {
          items: [
            {
              message_id: 'message_1', session_id: 'session_demo', message_type: 'user',
              content: '分析下载方向测速不达标原因，标准带宽 1 Gbps，实际带宽 20 Mbps。',
              created_at: now, evidence_count: 0,
            },
            {
              message_id: 'message_2', session_id: 'session_demo', message_type: 'assistant',
              content: '参数已确认，诊断已完成。可以查看报告、指标、TCP 流与证据。',
              created_at: now, evidence_count: 0,
            },
          ],
          total: 2,
          offset: 0,
          limit: 100,
        },
        parameters: {
          capture,
          standard_bandwidth_mbps: 1000,
          actual_bandwidth_mbps: 20,
          target: 'download',
          missing: [], assumptions: [], ambiguities: [], ready_for_confirmation: !hasAnalysis,
        },
      }
    } else if (url.pathname === '/api/analyses/analysis_demo') {
      data = {
        analysis: currentAnalysis,
        report_available: currentStatus === 'completed',
        recoverable: currentStatus === 'failed',
        suggested_action: currentStatus === 'failed' ? '请重试任务。' : '',
      }
    } else if (url.pathname.endsWith('/report')) {
      data = {
        analysis_id: 'analysis_demo',
        report: {
          standard_bandwidth_mbps: 1000,
          actual_bandwidth_mbps: 20,
          achievement_ratio_pct: 2,
          target: 'download',
          primary_cause: '接收窗口受限并伴随持续重传，吞吐在整个测速阶段明显低于标准带宽',
          candidate_causes: [
            {
              cause: '接收窗口限制', confidence: 91,
              explanation: '多个连续区间出现窗口满事件，RTT 增长后有效在途数据不足。',
              supporting_evidence: ['流 0 在 4.2 到 12.8 秒持续出现窗口满', '窗口最小值降至 4096 字节'],
              contradicting_evidence: ['未观察到零窗口'],
              missing_evidence: ['缺少端系统 TCP 缓冲区配置'],
              suggestion: '核对接收端窗口缩放和 TCP 缓冲区上限',
            },
            {
              cause: '链路丢包触发重传退避', confidence: 78,
              explanation: '异常区间内重传与重复 ACK 同步增加。',
              supporting_evidence: ['共识别 126 次重传'],
              contradicting_evidence: [], missing_evidence: [],
              suggestion: '检查链路误码和中间设备丢弃统计',
            },
          ],
          key_evidence: [], confidence: 88,
          coverage_summary: { complete: true, truncated: false },
          evidence_quality: {},
          limitations: ['报文不包含操作系统 TCP 参数'],
          troubleshooting_steps: ['检查接收端窗口缩放是否生效', '对照交换机接口丢包计数'],
          optimization_suggestions: ['增大 TCP 接收缓冲区', '排查链路丢包'],
          analysis_metadata: {},
        },
      }
    } else if (url.pathname.endsWith('/metrics')) {
      data = {
        tcp_summary: {
          packet_count: 284392, retransmission_count: 126, duplicate_ack_count: 89,
          out_of_order_count: 11, zero_window_count: 0, window_full_count: 214,
        },
        coverage_summary: { complete: true },
        intervals: Array.from({ length: 20 }, (_, i) => ({
          interval_start: i,
          throughput_mbps: i < 5 ? 28 - i : 18 + (i % 4),
        })),
        rtt_histogram: [
          { upper_bound_ms: 5, count: 120 },
          { upper_bound_ms: 20, count: 870 },
          { upper_bound_ms: 50, count: 440 },
          { upper_bound_ms: 'inf', count: 32 },
        ],
        top_flows: [], point_limit: 1000, downsampled: false,
      }
    } else if (url.pathname.endsWith('/flows')) {
      data = {
        items: [{
          flow_id: '10.10.1.20:443 -> 10.10.1.8:53241', direction: 'download',
          packet_count: 284392, payload_bytes: 443923122, throughput_mbps: 20.18,
          duration_seconds: 176, retransmission_count: 126, duplicate_ack_count: 89,
          out_of_order_count: 11, zero_window_count: 0, window_full_count: 214,
          window_min: 4096, window_max: 1048576,
        }],
        total: 1, offset: 0, limit: 50,
      }
    } else if (url.pathname.endsWith('/evidence')) {
      data = {
        analysis_id: 'analysis_demo', evidence_type: 'retransmission',
        items: [{
          frame_number: 18422, relative_time: 4.286,
          flow_id: '10.10.1.20:443 -> 10.10.1.8:53241',
          event_type: 'retransmission', tcp_seq: 829192, tcp_ack: 2014, tcp_window: 8192,
        }],
        total: 1, truncated: false, warnings: [],
      }
    } else if (url.pathname.endsWith('/chat')) {
      data = { items: [], total: 0, offset: 0, limit: 50 }
    } else {
      data = []
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: ok(data) })
  })
  return actions
}

async function expectNoViewportOverflow(page: Page) {
  const dimensions = await page.evaluate(() => ({
    width: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }))
  expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.width)
}

test('参数确认后启动任务并可从服务端状态恢复', async ({ page }) => {
  const actions = await mockApi(page, 'awaiting_confirmation')
  await page.goto('/')
  await expect(page.getByText('诊断参数已完整')).toBeVisible()
  await page.getByRole('button', { name: '开始分析' }).click()
  await expect.poll(() => actions).toContain('confirm')
  await expect(page.getByText('分析报文').first()).toBeVisible()
  await page.reload()
  await expect(page.getByText('分析报文').first()).toBeVisible()
})

test('运行中任务确认后取消且失败任务可以重试', async ({ page }) => {
  const actions = await mockApi(page, 'analyzing')
  const dialogs: string[] = []
  page.on('dialog', dialog => {
    dialogs.push(dialog.message())
    dialog.accept()
  })
  await page.goto('/')
  await page.getByTitle('取消分析').click()
  await expect.poll(() => actions).toContain('cancel')
  expect(dialogs).toEqual(['确定要取消当前分析任务吗？已完成的本地产物会保留。'])
  await expect(page.getByText('已取消').first()).toBeVisible()

  await page.unrouteAll({ behavior: 'wait' })
  const retryActions = await mockApi(page, 'failed')
  await page.reload()
  await page.getByRole('button', { name: '重试任务' }).click()
  await expect.poll(() => retryActions).toContain('retry')
  await expect(page.getByText('分析报文').first()).toBeVisible()
})

for (const viewport of [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'laptop', width: 1024, height: 768 },
  { name: 'narrow', width: 390, height: 844 },
]) {
  test(`${viewport.name} 工作台无溢出且核心视图可用`, async ({ page }, testInfo) => {
    const pageErrors: Error[] = []
    page.on('pageerror', error => pageErrors.push(error))
    await page.setViewportSize(viewport)
    await mockApi(page)
    await page.goto('/')
    await expect(page.getByText('PacketMaster', { exact: true })).toBeVisible()
    await expect(page.getByText('参数已确认，诊断已完成。可以查看报告、指标、TCP 流与证据。')).toBeVisible()
    await expectNoViewportOverflow(page)

    await page.getByRole('button', { name: '报告' }).click()
    await expect(page.getByText('接收窗口受限并伴随持续重传，吞吐在整个测速阶段明显低于标准带宽')).toBeVisible()
    await expectNoViewportOverflow(page)
    await page.screenshot({ path: testInfo.outputPath('report.png'), fullPage: true })

    await page.getByRole('button', { name: '指标' }).click()
    await expect(page.getByRole('img', { name: '吞吐量时间序列' })).toBeVisible()
    await expect(page.locator('.chart canvas')).toHaveCount(3)
    const painted = await page.locator('.chart canvas').first().evaluate(canvas => {
      const element = canvas as HTMLCanvasElement
      const context = element.getContext('2d')
      return context
        ? Array.from(context.getImageData(0, 0, element.width, element.height).data)
          .some((value, index) => index % 4 === 3 && value > 0)
        : false
    })
    expect(painted).toBe(true)
    await expectNoViewportOverflow(page)
    await page.screenshot({ path: testInfo.outputPath('metrics.png'), fullPage: true })

    await page.getByRole('button', { name: 'TCP 流' }).click()
    await expect(page.getByText('10.10.1.20:443 -> 10.10.1.8:53241')).toBeVisible()
    await page.getByRole('button', { name: '证据' }).click()
    await expect(page.getByText('18422')).toBeVisible()
    await expectNoViewportOverflow(page)
    expect(pageErrors).toEqual([])
  })
}
