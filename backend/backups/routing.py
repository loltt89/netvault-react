"""
WebSocket URL routing for backups app.
"""

from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r'ws/backup_logs/', consumers.BackupLogConsumer.as_asgi()),
]
