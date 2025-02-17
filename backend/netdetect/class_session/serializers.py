from rest_framework import serializers
from .models import *

class ClassSessionerializer(serializers.ModelSerializer):
    class Meta:
        model = classSession
        fields = ['subject', 'course', 'year_level', 'section', 'start_time', 'end_time', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'], 