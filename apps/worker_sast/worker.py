from __future__ import annotations

from celery import Celery

from packages.shared.settings import get_settings

settings = get_settings()
celery_app = Celery("worker_sast", broker=str(settings.redis_url), backend=str(settings.redis_url))
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_routes={"apps.worker_sast.tasks.*": {"queue": "sast"}},
    worker_prefetch_multiplier=1,
    task_soft_time_limit=120,
    task_time_limit=180,
)
