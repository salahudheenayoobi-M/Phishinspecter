from django.urls import path
from . import views

app_name = 'detector'

urlpatterns = [
    path('check_sms/', views.check_sms, name='check_sms'),
    path('sms_dashboard/', views.sms_dashboard, name='sms_dashboard'),
]