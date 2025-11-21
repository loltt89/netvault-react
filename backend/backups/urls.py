from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import BackupViewSet, BackupScheduleViewSet, BackupRetentionPolicyViewSet

router = DefaultRouter()
router.register(r'backups', BackupViewSet, basename='backup')
router.register(r'schedules', BackupScheduleViewSet, basename='backupschedule')
router.register(r'retention-policies', BackupRetentionPolicyViewSet, basename='retentionpolicy')

urlpatterns = [
    path('', include(router.urls)),
]
