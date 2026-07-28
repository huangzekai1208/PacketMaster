// ECharts 的按需注册与 React 生命周期封装，避免重复初始化 Canvas 实例。
import { BarChart, LineChart } from 'echarts/charts'
import { GridComponent, TitleComponent, TooltipComponent } from 'echarts/components'
import * as echarts from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { useEffect, useRef } from 'react'

echarts.use([BarChart, LineChart, GridComponent, TitleComponent, TooltipComponent, CanvasRenderer])

export default function Chart({ option, label }: { option: echarts.EChartsCoreOption; label: string }) {
  // ResizeObserver 让图表随工作台栏宽变化重新布局。
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!ref.current) return
    const chart = echarts.init(ref.current)
    chart.setOption(option)
    const observer = new ResizeObserver(() => chart.resize())
    observer.observe(ref.current)
    return () => { observer.disconnect(); chart.dispose() }
  }, [option])
  return <div ref={ref} className="chart" role="img" aria-label={label} />
}
