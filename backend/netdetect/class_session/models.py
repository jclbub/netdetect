from django.db import models

# Create your models here.
class classSession(models.Model):
    subject = models.CharField( max_length=50)
    course = models.CharField( max_length=50)
    year_level = models.CharField( max_length=50)
    section = models.CharField( max_length=50)
    start_time = models.TimeField()
    end_time = models.TimeField()
    monday = models.BooleanField(default=False)
    tuesday = models.BooleanField(default=False)
    wednesday = models.BooleanField(default=False)
    thursday = models.BooleanField(default=False)
    friday = models.BooleanField(default=False)
    saturday = models.BooleanField(default=False)

    class Meta:
        unique_together = ('subject', 'course', 'year_level', 'section')