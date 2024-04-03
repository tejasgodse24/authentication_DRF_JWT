from django.urls import path
from .views import *

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name="register"),
    path('login/', UserLoginView.as_view(), name="login"),
    path('profile/', UserProfileView.as_view(), name="user_profile"),
    path('change-password/', UserChangePasswordView.as_view(), name="user_changepassword"),
    path('send-resetpass-email/', SendPasswordResetEmailView.as_view(), name="user_sendresetpassemail"),
    path('reset-password/<uid>/<token>/', UserPasswordReserView.as_view(), name="user_resetpassword"),
]
