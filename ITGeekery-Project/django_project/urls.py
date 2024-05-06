#DJANGO PROJECT URL
from django.contrib import admin
from django.urls import path, include, re_path
from django.views.generic import RedirectView
from django.contrib.auth import views as auth_views
from django.conf import settings


urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', auth_views.LoginView.as_view(template_name='dashboard/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('signup/', include('dashboard.urls')),
    path('dashboard/', include('dashboard.urls')),
    re_path(r'^$', RedirectView.as_view(url='/login/', permanent=False)),
]