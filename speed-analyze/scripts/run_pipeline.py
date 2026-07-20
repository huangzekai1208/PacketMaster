"""
测速分析流水线 - 串联筛选 + TCP 提取

将 speed_filter_strip.py 和 tcp_extract.py 串成一个流水线，
AI 只需一次 Bash 调用即可完成 Steps 2-3，无需轮询等待。

用法：
  python run_pipeline.py --input <pcapng> --target <download|upload|both> --output output
  python run_pipeline.py --input <pcapng> --target download --output output --max-packets 5000

输出：
  output/<stem>_download.pcapng              筛选后的下载报文
  output/<stem>_upload.pcapng                筛选后的上行报文
  output/<stem>_speed_stats.json             测速流统计
  output/<stem>_download_tcp_analysis.json   TCP 分析数据
  output/log/<timestamp>_pipeline.log        运行日志
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime

# Windows 下强制 stdout/stderr 使用 UTF-8，避免中文路径/日志的 GBK 编码错误
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


# ============================================================
# 日志
# ============================================================

def setup_logger(output_dir):
    log_dir = os.path.join(output_dir, "log")
    os.makedirs(log_dir, exist_ok=True)
    _log_tmp = os.path.join(log_dir, "_running_pipeline.tmp")

    # 简易 logger：同时写 stdout 和文件
    class Logger:
        def __init__(self, fh):
            self._fh = fh

        def info(self, msg):
            print(msg, flush=True)
            self._fh.write(msg + "\n")
            self._fh.flush()

        def error(self, msg):
            print(f"[ERROR] {msg}", flush=True)
            self._fh.write(f"[ERROR] {msg}\n")
            self._fh.flush()

    fh = open(_log_tmp, "w", encoding="utf-8")
    return Logger(fh), _log_tmp


def close_logger(log_tmp_path):
    log_dir = os.path.dirname(log_tmp_path)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    final_path = os.path.join(log_dir, f"{ts}_pipeline.log")
    # 先关闭文件句柄再重命名
    import io
    if hasattr(log_tmp_path, 'close'):
        pass  # 调用者负责关闭
    if os.path.exists(log_tmp_path):
        try:
            os.rename(log_tmp_path, final_path)
        except OSError:
            pass


# ============================================================
# 子进程运行（实时输出）
# ============================================================

def run_script(cmd, logger):
    """运行子脚本，实时输出 stdout 到 logger。返回 exit code。"""
    logger.info(f"  命令: {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                logger.info(f"  {line}")
        proc.wait()
        return proc.returncode
    except FileNotFoundError:
        logger.error(f"  脚本未找到: {cmd[0]}")
        return 1
    except Exception as e:
        logger.error(f"  运行异常: {e}")
        return 1


# ============================================================
# 主流程
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="测速分析流水线（筛选 + TCP 提取）")
    parser.add_argument("--input", required=True, help="输入 pcapng 文件路径")
    parser.add_argument("--target", default="download",
                        choices=["upload", "download", "both"],
                        help="分析方向（默认: download）")
    parser.add_argument("--output", default="output", help="输出目录（默认: output）")
    parser.add_argument("--max-packets", type=int, default=5000,
                        help="TCP 提取最大报文数（默认: 5000）")
    parser.add_argument("--min-ratio", type=float, default=0.70,
                        help="单向流量占比阈值（默认: 0.70）")
    parser.add_argument("--min-bytes", type=int, default=102400,
                        help="最小流量字节数（默认: 102400）")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    logger, log_tmp = setup_logger(args.output)

    input_stem = os.path.splitext(os.path.basename(args.input))[0]
    script_dir = os.path.dirname(os.path.abspath(__file__))

    logger.info("=" * 60)
    logger.info("测速分析流水线启动")
    logger.info(f"  输入: {args.input}")
    logger.info(f"  方向: {args.target}")
    logger.info(f"  输出: {args.output}")
    logger.info("=" * 60)

    # ============================================================
    # Step 1: 测速流筛选
    # ============================================================
    logger.info("\n[Step 1/2] 运行测速流筛选 (speed_filter_strip.py)...")

    filter_script = os.path.join(script_dir, "speed_filter_strip.py")
    filter_cmd = [
        sys.executable, filter_script,
        "--input", args.input,
        "--target", args.target,
        "--output", args.output,
        "--min-ratio", str(args.min_ratio),
        "--min-bytes", str(args.min_bytes),
    ]

    rc = run_script(filter_cmd, logger)
    if rc != 0:
        logger.error(f"测速流筛选失败 (exit code {rc})，流水线中止。")
        close_logger(log_tmp)
        sys.exit(1)

    stats_json = os.path.join(args.output, f"{input_stem}_speed_stats.json")
    if not os.path.exists(stats_json):
        logger.error(f"未找到统计文件: {stats_json}，流水线中止。")
        close_logger(log_tmp)
        sys.exit(1)

    logger.info("[Step 1/2] 测速流筛选完成。")

    # ============================================================
    # 读取 speed_stats.json，确定端口和 pcapng 路径
    # ============================================================
    with open(stats_json, "r", encoding="utf-8") as f:
        stats = json.load(f)

    download_count = stats.get("download_flows_count", 0)
    upload_count = stats.get("upload_flows_count", 0)
    logger.info(f"  下载流: {download_count} 条，上行流: {upload_count} 条")

    # 从测速流中提取端口号
    speed_flows = stats.get("speed_flows", [])
    ports = set()
    for flow in speed_flows:
        ports.add(flow.get("dport"))
        ports.add(flow.get("sport"))
    # 过滤掉 None 和非数值端口
    ports = sorted([p for p in ports if isinstance(p, int)])

    # 确定需要 TCP 分析的方向和对应 pcapng
    targets = []
    if args.target in ("download", "both") and download_count > 0:
        pcap_path = os.path.join(args.output, f"{input_stem}_download.pcapng")
        if os.path.exists(pcap_path):
            targets.append(("download", pcap_path))
    if args.target in ("upload", "both") and upload_count > 0:
        pcap_path = os.path.join(args.output, f"{input_stem}_upload.pcapng")
        if os.path.exists(pcap_path):
            targets.append(("upload", pcap_path))

    if not targets:
        logger.error("未找到任何可分析的测速流 pcapng 文件，流水线中止。")
        close_logger(log_tmp)
        sys.exit(1)

    # ============================================================
    # Step 2: TCP 字段提取（每个方向各跑一次）
    # ============================================================
    extract_script = os.path.join(script_dir, "tcp_extract.py")

    for direction, pcap_path in targets:
        logger.info(f"\n[Step 2/2] 运行 TCP 字段提取 ({direction}) (tcp_extract.py)...")

        for port in ports:
            extract_cmd = [
                sys.executable, extract_script,
                "--input", pcap_path,
                "--port", str(port),
                "--output", args.output,
                "--max-packets", str(args.max_packets),
                "--stats", stats_json,
            ]

            rc = run_script(extract_cmd, logger)
            if rc != 0:
                logger.error(f"TCP 提取失败 (方向={direction}, 端口={port}, exit code {rc})，跳过。")
                continue

            # tcp_extract.py 输出文件名: {stem}_tcp_analysis.json
            # 只需第一个端口的结果即可（同一方向所有端口属于同一次测速）
            logger.info(f"[Step 2/2] TCP 字段提取 ({direction}) 完成。")
            break  # 同方向只需分析一个端口

    # ============================================================
    # 完成
    # ============================================================
    logger.info("\n" + "=" * 60)
    logger.info("流水线处理完成！输出文件：")

    for f in os.listdir(args.output):
        fpath = os.path.join(args.output, f)
        if os.path.isfile(fpath) and not f.startswith("_"):
            size_mb = os.path.getsize(fpath) / (1024 * 1024)
            logger.info(f"  {f} ({size_mb:.1f} MB)")

    logger.info("=" * 60)

    close_logger(log_tmp)


if __name__ == "__main__":
    main()
