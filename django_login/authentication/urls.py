from django.urls import path

from .views import (
    LoginAPIView, RegistrationAPIView, UserRetrieveUpdateAPIView,
    RequestResetAPIView, ResetPasswordAPIView, ActivateAccountAPIView
)


urlpatterns = [
    path('user/', UserRetrieveUpdateAPIView.as_view()),
    path('users/', RegistrationAPIView.as_view(), name="create_user"),
    path('users/login', LoginAPIView.as_view(), name="user_login"),
    path("resetrequest", RequestResetAPIView.as_view(), name="reset_request"),
    path("resetpassword/<str:token>",
         ResetPasswordAPIView.as_view(), name='reset_password'),
    path(
        "activate/account/<str:pk>/<str:token>",
        ActivateAccountAPIView.as_view(), name="activate_account"
    ),
]
