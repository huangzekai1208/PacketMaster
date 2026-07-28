"""不依赖 CLI 或 Web 界面的 PacketMaster 应用服务导出。"""

from packetmaster.application.diagnosis import (
    DiagnosisOutcome,
    DiagnosisProgress,
    DiagnosisService,
)

__all__ = ["DiagnosisOutcome", "DiagnosisProgress", "DiagnosisService"]
