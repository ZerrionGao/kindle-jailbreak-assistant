"""面向用户的阶段进度事件模型。"""

from dataclasses import dataclass

from .models import Stage


@dataclass(frozen=True)
class ProgressEvent:
    event: str
    stage: Stage
    message: str
    done: int | None = None
    total: int | None = None
    unit: str | None = None
    user_action: str | None = None

    def to_dict(self) -> dict[str, object]:
        """返回可直接编码为单行 JSON 的事件数据。"""

        return {
            "event": self.event,
            "stage": self.stage.value,
            "message": self.message,
            "done": self.done,
            "total": self.total,
            "unit": self.unit,
            "user_action": self.user_action,
        }
