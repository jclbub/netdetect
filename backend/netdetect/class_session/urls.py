from django.contrib import admin
from django.urls import include, path
from .views import *
urlpatterns = [
    path('create/', CreateClassSessionView),
    path('update/', UpdateClassSessionView),
    path('delete/', DeleteClassSessionView),
]
