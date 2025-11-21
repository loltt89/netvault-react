"""
WebSocket consumers for real-time backup logs.
"""

import json
from channels.generic.websocket import AsyncWebsocketConsumer


class BackupLogConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer that streams backup task logs to authenticated users in real-time.
    Each user has their own group (room) to receive logs only for their triggered tasks.
    """

    async def connect(self):
        """
        Called when WebSocket connection is established.
        Only authenticated users are allowed to connect.
        """
        user = self.scope.get("user")

        # Check if user is authenticated
        if user and user.is_authenticated:
            self.user = user
            self.group_name = f'user_{self.user.id}_logs'

            # Join user-specific group
            await self.channel_layer.group_add(
                self.group_name,
                self.channel_name
            )

            # Accept the WebSocket connection
            await self.accept()
        else:
            # Reject connection if user is not authenticated
            await self.close(code=4001)  # Custom close code for unauthorized

    async def disconnect(self, close_code):
        """
        Called when WebSocket connection is closed.
        """
        if hasattr(self, 'group_name'):
            # Leave the user-specific group
            await self.channel_layer.group_discard(
                self.group_name,
                self.channel_name
            )

    async def receive(self, text_data):
        """
        Called when a message is received from the WebSocket (client -> server).
        Currently not used, but can be extended for client commands.
        """
        pass

    async def send_log_message(self, event):
        """
        Called when a message is sent to this consumer's group.
        This is invoked by Celery tasks via channel_layer.group_send().
        """
        message = event.get('message', {})

        # Send the log message to WebSocket client
        await self.send(text_data=json.dumps(message))
