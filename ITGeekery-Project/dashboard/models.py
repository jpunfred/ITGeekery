from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    company = models.CharField(max_length=100)
    occupation = models.CharField(max_length=100)
    keywords = models.TextField()
    tickets_url = models.URLField(default='', blank=True)
    device_management_url = models.URLField(default='', blank=True)
    company_homepage_url = models.URLField(default='', blank=True)

    def __str__(self) -> str:
      return self.user.username

