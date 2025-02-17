from django.contrib import admin
from django.urls import include, path
from accounts.views import ContactMessageView
urlpatterns = [
    path('admin', admin.site.urls),
    path('auth/', include('djoser.urls')),
    path('auth/', include('djoser.urls.jwt'), name="jwt"),
    path('auth/', include("djoser.urls.authtoken")),
    path('auth/', include('djoser.social.urls')),
    path('contact/', ContactMessageView),
    path('classSession/', include('class_session.urls')),
]
