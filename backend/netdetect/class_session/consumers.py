import json
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async
from channels.db import database_sync_to_async
from .serializers import *
from .models import *
from accounts.serializers import *
from accounts.models import *

# Base Consumer to handle common WebSocket operations
class BaseConsumer(AsyncWebsocketConsumer):
    group_name = None

    async def connect(self):
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        await self.send_data()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def send_data(self):
        raise NotImplementedError("Subclasses must implement send_data")

    async def update(self, event):
        await self.send_data()

class ClassConsumer(BaseConsumer):
    group_name = 'class_group'

    @database_sync_to_async
    def all_classes(self):
        classes = classSession.objects.all()
        class_serializer = class_serializer(classes, many=True)
        return class_serializer.data

    async def send_data(self):
        classes = await self.all_classes()
        await self.send(json.dumps({"Classes": classes}))