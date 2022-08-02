from django.db import models


# Create your models here.
class UserData(models.Model):
    ip = models.CharField(max_length=100)
    browser = models.CharField(max_length=50)
    device = models.CharField(max_length=50)
    os = models.CharField(max_length=50)
    platform = models.CharField(max_length=50)
