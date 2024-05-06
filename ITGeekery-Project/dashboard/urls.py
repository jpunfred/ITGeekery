from django.urls import path
from . import views
from .views import fetch_cves

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('signup/', views.signup, name='signup'),
    path('account/', views.account_management, name='account'),
    path('cves/', fetch_cves, name='fetch_cves'),
    path('network-status/', views.fetch_network_status, name='fetch_network_status'),
]
