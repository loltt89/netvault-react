from django.db import models
from django.conf import settings


class NotificationRule(models.Model):
    """Rules for when to send notifications"""

    TRIGGER_CHOICES = (
        ('backup_failed', 'Backup Failed'),
        ('backup_success', 'Backup Success'),
        ('device_offline', 'Device Offline'),
        ('config_changed', 'Configuration Changed'),
        ('critical_change', 'Critical Change'),
    )

    CHANNEL_CHOICES = (
        ('email', 'Email'),
        ('telegram', 'Telegram'),
        ('webhook', 'Webhook'),
    )

    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    trigger = models.CharField(max_length=50, choices=TRIGGER_CHOICES)
    channel = models.CharField(max_length=20, choices=CHANNEL_CHOICES)
    is_active = models.BooleanField(default=True)

    # Recipients
    email_recipients = models.JSONField(default=list)  # List of email addresses
    telegram_chat_ids = models.JSONField(default=list)  # List of Telegram chat IDs
    webhook_url = models.URLField(blank=True)

    # Filters
    device_filters = models.JSONField(default=dict)  # Filter by device properties

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='notification_rules_created'
    )

    class Meta:
        db_table = 'notification_rules'
        verbose_name = 'Notification Rule'
        verbose_name_plural = 'Notification Rules'
        ordering = ['name']

    def __str__(self):
        return f'{self.name} - {self.get_trigger_display()} via {self.get_channel_display()}'


class Notification(models.Model):
    """Notification log"""

    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('sent', 'Sent'),
        ('failed', 'Failed'),
    )

    rule = models.ForeignKey(NotificationRule, on_delete=models.SET_NULL, null=True, related_name='notifications')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    title = models.CharField(max_length=255)
    message = models.TextField()
    channel = models.CharField(max_length=20)
    recipient = models.CharField(max_length=255)

    sent_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'notifications'
        verbose_name = 'Notification'
        verbose_name_plural = 'Notifications'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.title} - {self.status}'
