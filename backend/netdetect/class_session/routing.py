from django.urls import path
from .consumers import *

websocket_urlpatterns = [
    path('ws/class/', ClassConsumer.as_asgi()),
]