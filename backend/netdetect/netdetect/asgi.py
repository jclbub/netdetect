import os

from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from channels.security.websocket import AllowedHostsOriginValidator
from class_session import routing as class_route
from network import routing as network_route
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netdetect.settings')

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AllowedHostsOriginValidator(
        AuthMiddlewareStack(
            URLRouter(
                class_route.websocket_urlpatterns + network_route.websocket_urlpatterns
                # + accounts_route.websocket_urlpatterns
            )
        )
    ),
})
