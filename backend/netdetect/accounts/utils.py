from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

# Utility to send updates to WebSocket group
def send_group_update(group_name, message_type):
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        group_name,  # WebSocket group name
        {"type": message_type}  # Message payload
    )

# Specific functions for each consumer group
def send_student_update():
    send_group_update("student_group", "update")

