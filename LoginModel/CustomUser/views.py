from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializer import *
from django.contrib.auth import authenticate
from CustomUser.models import User

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated


# Generate Token Manually
def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)
  return {
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  }

# Create your views here.

class UserRegisterView(APIView):
    def post(self,request,format=None):
        serializer=UserRegisterSerializer(data=request.data)
        
        if serializer.is_valid():
            user=serializer.save()
            return Response({'message':"registration success"}
                            ,status=status.HTTP_201_CREATED)
        print(serializer.errors)
        
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class UserloginView(APIView):
  
  def post(self, request, format=None):
    serializer = UserloginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    email = serializer.data.get('email')
    password = serializer.data.get('password')
    user = authenticate(email=email, password=password)
    if user is not None:
      token = get_tokens_for_user(user)
      return Response({"token":token,'msg':'Login Success'}, status=status.HTTP_200_OK)
    else:
      return Response({'errors':{'Invalid data':['email or eassword is not Valid']}}, status=status.HTTP_404_NOT_FOUND)

class UserChangePassword(APIView):
   permission_classes=[IsAuthenticated]
   def post(self,request,format=None):
      serializer=UserChangePasswordSerializer(data=request.data,context={"user":request.user})
      
      if serializer.is_valid(raise_exception=True):
         return Response({"status":200,"msg":"password changed successfully"})

      return Response({"error":serializer.errors},status.HTTP_400_BAD_REQUEST)         
      
# to send email for reset password
class SendPasswordResetEmail(APIView):

  def post(self, request, format=None):
    serializer = SendPasswordResetEmailSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)
  

class UserPasswordReset(APIView):
   def post(self,request,uid,token,format=None):
      serializer=UserPasswordResetSerializer(data=request.data,context={"uid":uid,"token":token})
      serializer.is_valid(raise_exception=True)
      
      return Response({"msg":"password reset successfully"})