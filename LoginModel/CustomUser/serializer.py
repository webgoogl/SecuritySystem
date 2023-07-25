from rest_framework import serializers
from CustomUser.models import User
from django.contrib.auth import authenticate
from rest_framework.response import Response
from django.utils.encoding import smart_str,force_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .utils import *

class UserRegisterSerializer(serializers.ModelSerializer):
    password2=serializers.CharField(style={"input_type":"password"},write_only=True)
    class Meta:
        model=User
        fields=['email','name','password','password2']
        extra_kwargs={
            "password":{"write_only":True}
        }

    def validate(self, attrs):
        password=attrs.get('password')
        password2=attrs.get('password2')
        if password!=password2:
            raise serializers.ValidationError({"error":"pass and confirm pass does't match"})
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
    
class UserloginSerializer(serializers.ModelSerializer):

    # if we can't define email here so we will a error here that is email already exist
    email = serializers.EmailField(max_length=255)
    class Meta:
        model=User
        fields=['email','password']


# to change user password
class UserChangePasswordSerializer(serializers.Serializer):
    password=serializers.CharField(max_length=255,style=
                                   {'input_type':'password'},write_only=True)
    password2=serializers.CharField(max_length=255,style=
                                    {'input_type':'password'},write_only=True)

    class Meta:
        model=User
        fields=['password','password2']

    def validate(self, attrs):
        password=attrs.get("password")
        password2=attrs.get("password2")
        user=self.context.get('user')
        if password!=password2:
            raise serializers.ValidationError({"error":"password and confirm password does't match"})
        user.set_password(password)
        user.save()
        return attrs


class SendPasswordResetEmailSerializer(serializers.Serializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    fields = ['email']

  def validate(self, attrs):
    email = attrs.get('email')
    if User.objects.filter(email=email).exists():
      user = User.objects.get(email = email)
      uid = urlsafe_base64_encode(force_bytes(user.id))
      
      token = PasswordResetTokenGenerator().make_token(user)
      print('Password Reset Token', token)
      link = 'http://127.0.0.1:8000/api/rest-password/'+uid+'/'+token
      print("Reset link : ",link)
      # mail

      body = 'Click Following Link to Reset Your Password '+link
      data = {
        'subject':'Reset Your Password',
        'body':body,
        'to_email':user.email
      }
     
      if Util.send_email(data)==False:
          raise serializers.ValidationError({"error":"email not sent"})
      elif Util.send_email(data)==True:
          return True
    
      return attrs
    else:
      raise serializers.ValidationError({'invalid user':'You are not a Registered'})
    
class UserPasswordResetSerializer(serializers.Serializer):
    password=serializers.CharField(max_length=255,style=
                                   {'input_type':'password'},write_only=True)
    password2=serializers.CharField(max_length=255,style=
                                    {'input_type':'password'},write_only=True)

    class Meta:
        model=User
        fields=['password','password2']

    def validate(self, attrs):
        password=attrs.get("password")
        password2=attrs.get("password2")
        uid=self.context.get('uid')
        token=self.context.get('token')
        if password!=password2:
            raise serializers.ValidationError({"error":"password and confirm password does't match"})
        id=smart_str(urlsafe_base64_decode(uid))
        user=User.objects.get(id=id)
        if not PasswordResetTokenGenerator().check_token(user,token):
            raise serializers.ValidationError({"msg":"this link is expire"})
        user.set_password(password)
        user.save()
        return attrs