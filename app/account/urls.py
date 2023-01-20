from django.urls import path

from . import views

app_name = 'account'

urlpatterns = [
    path('signup/', views.signup_request, name='signup'),
    path('login/', views.login_request, name='login'),
    path('logout/', views.logout_request, name='logout'),
    path('otp/', views.otp_request, name='otp'),
    path('send_otp/', views.send_otp, name='send_otp'),
]
