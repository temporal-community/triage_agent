from temporalio import activity
from activities.models import SocketSignals


@activity.defn(name="activities.socket.score")
async def score(ecosystem: str, package: str, old_version: str, new_version: str) -> SocketSignals:
    activity.logger.info(f"[stub] Fetching Socket score for {package} {new_version}")
    return SocketSignals(socket_score=85, socket_alerts=[])
