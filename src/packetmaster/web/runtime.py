"""本机 PacketMaster Web 工作区的跨平台启动、端口与进程生命周期。"""

from __future__ import annotations

import multiprocessing
import socket
import threading
import webbrowser
from collections.abc import Callable
from pathlib import Path

from packetmaster.config import Settings
from packetmaster.errors import AppError
from packetmaster.web.api import create_app
from packetmaster.web.worker import run_worker_process


def static_directory() -> Path:
    return Path(__file__).with_name("static")


def find_available_port(host: str, preferred: int, *, attempts: int = 20) -> int:
    for port in range(preferred, preferred + attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
            try:
                candidate.bind((host, port))
            except OSError:
                continue
            return port
    raise AppError(
        code="WEB_PORT_UNAVAILABLE",
        message="没有可用的本机 Web 端口",
        recoverable=True,
        suggested_action="请关闭占用端口的程序，或修改 WEB_PORT 后重试。",
    )


def run_web(
    settings: Settings,
    *,
    open_browser: bool = True,
    announce: Callable[[str], None] | None = None,
) -> str:
    root = static_directory()
    if not root.joinpath("index.html").is_file():
        raise AppError(
            code="WEB_ASSETS_UNAVAILABLE",
            message="PacketMaster Web 前端资源缺失",
            recoverable=False,
            suggested_action="请重新安装 PacketMaster，或先执行前端生产构建。",
        )
    try:
        import uvicorn
    except ImportError as exc:
        raise AppError(
            code="WEB_DEPENDENCY_UNAVAILABLE",
            message="PacketMaster Web 运行依赖未安装",
            recoverable=False,
            suggested_action="请重新安装项目 requirements。",
        ) from exc

    port = find_available_port(settings.web_host, settings.web_port)
    url = f"http://{settings.web_host}:{port}"
    application = create_app(settings, static_directory=root)
    context = multiprocessing.get_context("spawn")
    stop_event = context.Event()
    worker = context.Process(
        target=run_worker_process,
        args=(str(settings.web_database_path), settings, stop_event),
        name="packetmaster-worker",
        daemon=False,
    )
    worker.start()
    server = uvicorn.Server(
        uvicorn.Config(
            application,
            host=settings.web_host,
            port=port,
            log_level="info",
            access_log=False,
        )
    )
    if announce is not None:
        announce(url)
    browser_timer = None
    if open_browser:
        browser_timer = threading.Timer(0.8, webbrowser.open, args=(url,))
        browser_timer.daemon = True
        browser_timer.start()
    try:
        server.run()
    finally:
        if browser_timer is not None:
            browser_timer.cancel()
        stop_event.set()
        worker.join(timeout=10)
        if worker.is_alive():
            worker.terminate()
            worker.join(timeout=5)
    return url
