from django.urls import path
from .consumers import *

websocket_urlpatterns = [
    path('ws/network-monitor/', NetworkMonitorConsumer.as_asgi()),
    path('ws/network-scanner/', NetworkScannerConsumer.as_asgi()),
    
]