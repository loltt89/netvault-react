from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.db.models import Q, Count
from accounts.permissions import CanManageDevices
from .models import Vendor, DeviceType, DeviceGroup, Device
from .serializers import (
    VendorSerializer, DeviceTypeSerializer, DeviceGroupSerializer,
    DeviceSerializer, DeviceCreateSerializer, DeviceDetailSerializer
)


class VendorViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Vendor CRUD operations
    """
    queryset = Vendor.objects.all()
    serializer_class = VendorSerializer
    permission_classes = [IsAuthenticated, CanManageDevices]
    search_fields = ['name', 'slug']
    ordering_fields = ['name', 'created_at']
    ordering = ['name']
    pagination_class = None  # Disable pagination for vendors


class DeviceTypeViewSet(viewsets.ModelViewSet):
    """
    ViewSet for DeviceType CRUD operations
    """
    queryset = DeviceType.objects.all()
    serializer_class = DeviceTypeSerializer
    permission_classes = [IsAuthenticated, CanManageDevices]
    search_fields = ['name', 'slug']
    ordering_fields = ['name']
    ordering = ['name']
    pagination_class = None  # Disable pagination for device types

    def destroy(self, request, *args, **kwargs):
        """Prevent deletion of predefined device types"""
        device_type = self.get_object()

        # Check if predefined
        if device_type.is_predefined:
            return Response(
                {'error': 'Cannot delete predefined device type'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if in use by devices
        if device_type.devices.exists():
            return Response(
                {'error': f'Cannot delete device type. It is used by {device_type.devices.count()} device(s).'},
                status=status.HTTP_400_BAD_REQUEST
            )

        return super().destroy(request, *args, **kwargs)


class DeviceGroupViewSet(viewsets.ModelViewSet):
    """
    ViewSet for DeviceGroup CRUD operations
    """
    queryset = DeviceGroup.objects.annotate(device_count=Count('devices'))
    serializer_class = DeviceGroupSerializer
    permission_classes = [IsAuthenticated, CanManageDevices]
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'created_at']
    ordering = ['name']


class DeviceViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Device CRUD operations
    """
    queryset = Device.objects.select_related('vendor', 'device_type', 'group', 'created_by')
    permission_classes = [IsAuthenticated, CanManageDevices]
    search_fields = ['name', 'ip_address', 'location', 'description']
    ordering_fields = ['name', 'ip_address', 'created_at', 'last_backup']
    ordering = ['name']
    filterset_fields = ['vendor', 'device_type', 'group', 'status', 'criticality', 'protocol']

    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'retrieve':
            return DeviceDetailSerializer
        elif self.action in ['create', 'update', 'partial_update']:
            return DeviceCreateSerializer
        return DeviceSerializer

    def get_queryset(self):
        """Filter queryset based on query params"""
        queryset = super().get_queryset()

        # Filter by status
        status_param = self.request.query_params.get('status', None)
        if status_param:
            queryset = queryset.filter(status=status_param)

        # Filter by criticality
        criticality = self.request.query_params.get('criticality', None)
        if criticality:
            queryset = queryset.filter(criticality=criticality)

        # Filter by backup enabled
        backup_enabled = self.request.query_params.get('backup_enabled', None)
        if backup_enabled is not None:
            queryset = queryset.filter(backup_enabled=backup_enabled.lower() == 'true')

        # Search across multiple fields
        search = self.request.query_params.get('search', None)
        if search:
            queryset = queryset.filter(
                Q(name__icontains=search) |
                Q(ip_address__icontains=search) |
                Q(location__icontains=search) |
                Q(description__icontains=search)
            )

        return queryset

    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get device statistics"""
        total = Device.objects.count()
        by_status = dict(Device.objects.values('status').annotate(count=Count('id')).values_list('status', 'count'))
        by_criticality = dict(Device.objects.values('criticality').annotate(count=Count('id')).values_list('criticality', 'count'))
        by_vendor = list(Device.objects.values('vendor__name').annotate(count=Count('id')).values('vendor__name', 'count'))

        backup_enabled = Device.objects.filter(backup_enabled=True).count()

        return Response({
            'total': total,
            'by_status': by_status,
            'by_criticality': by_criticality,
            'by_vendor': by_vendor,
            'backup_enabled': backup_enabled,
        })

    @action(detail=True, methods=['post'])
    def test_connection(self, request, pk=None):
        """Test connection to device"""
        from .connection import test_connection
        from django.utils import timezone

        device = self.get_object()

        try:
            username = device.username
            password = device.get_password()
            enable_password = device.get_enable_password() if device.enable_password_encrypted else None

            success, message = test_connection(
                host=device.ip_address,
                port=device.port,
                protocol=device.protocol,
                username=username,
                password=password,
                enable_password=enable_password,
                timeout=30
            )

            # Update device status based on connection test result
            if success:
                device.status = 'online'
                device.last_seen = timezone.now()
            else:
                device.status = 'offline'
            device.save()

            return Response({
                'success': success,
                'message': message,
                'device_id': device.id,
                'device_name': device.name,
                'status': device.status,
            })

        except Exception as e:
            # Update device status to offline on exception
            device.status = 'offline'
            device.save()

            return Response({
                'success': False,
                'message': str(e),
                'device_id': device.id,
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['post'])
    def backup_now(self, request, pk=None):
        """Trigger immediate backup for device (works regardless of backup_enabled status)"""
        from backups.tasks import backup_device

        device = self.get_object()

        # Manual backup works regardless of backup_enabled setting
        # Only automatic scheduled backups respect backup_enabled

        # Trigger backup task
        task = backup_device.delay(
            device_id=device.id,
            triggered_by_id=request.user.id,
            backup_type='manual'
        )

        return Response({
            'success': True,
            'message': f'Backup initiated for {device.name}',
            'device_id': device.id,
            'task_id': task.id,
        }, status=status.HTTP_202_ACCEPTED)
