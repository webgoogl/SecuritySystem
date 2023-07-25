from django.contrib import admin
from django.urls import path,include
from CustomUser.views import *

urlpatterns = [
    path('send/',SendPasswordResetEmail.as_view()),
    path('register/',UserRegisterView.as_view()),
    path('changepassword/',UserChangePassword.as_view()),
    path('login/',UserloginView.as_view()),
    path('admin/', admin.site.urls),
    path('rest-password/<uid>/<token>/',UserPasswordReset.as_view()),
]
