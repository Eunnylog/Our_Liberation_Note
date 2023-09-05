import os
from pathlib import Path

from celery import Celery
from celery.schedules import crontab

# Absolute filesystem path to the top-level project folder:
BASE_DIR = Path(__file__).resolve(strict=True).parent.parent

# 설정되어있는 경우 환경변수 'DJANGO_SETTINGS_MODULE'를 가리키게 한다.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Our_Liberation_Note.settings")


CELERY_BROKER = "redis://localhost:6379"
CELERY_BACKEND = "redis://localhost:6379"
app = Celery("Our_Liberation_Note")

# Django 설정 파일에 있는 설정을 사용하도록 한다.
app.config_from_object("django.conf:settings", namespace="CELERY")


# 개별 앱중에서 작업자를 작동시킨다.
app.autodiscover_tasks()

app.conf.broker_connection_retry_on_startup = True

app.conf.beat_schedule = {
    'clear_expired_tokens_every_hour': {
        'task': 'user.tasks.clear_expired_tokens',
        # 'schedule': 3600.0  # every hour
        # 'schedule': 1.0  # every hour
        'schedule': 10.0  # every hour
    }
}