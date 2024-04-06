from rest_framework import serializers
from account.models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .utils import Util

class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    class Meta:
        model = User
        fields = ['email', 'name', 'password', 'password2', 'tc']
        extra_kwargs = {
            'password' : {'write_only': True}
        }

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("Password does not match")
        return attrs
    
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
    

class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length = 255)
    class Meta:
        model = User
        fields = ['email', 'password']


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'name', 'email', 'tc']


class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ["password", 'password2']
    
    def validate(self, attrs):
        password = attrs['password']
        password2 = attrs['password2']
        user = self.context.get("user")
        if password != password2:
            raise serializers.ValidationError("Password does not match")
        user.set_password(password)
        user.save()
        return attrs
    

class SendPasswordResetViewSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length= 255)
    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs['email']
        user_obj = User.objects.filter(email = email)
        if user_obj.exists():
            uid = urlsafe_base64_encode(force_bytes(user_obj[0].id))
            print(uid)
            token = PasswordResetTokenGenerator().make_token(user_obj[0])
            print(token)
            # link = "http://localhost:8000/api/user/reset-password/"+uid+"/"+token     #link for drf only
            link = "http://localhost:5173/api/user/reset-password/"+uid+"/"+token       #link for reactjs ui

            print(link)
            # send email 
            data = {
                "subject":"Reset Password Link",
                "body" : f"Click following link to reset password {link}",
                "to_email" : user_obj[0].email
            }
            Util.send_email(data)
        else:
            raise serializers.ValidationError("Email is Not registered")
        return attrs
    
class UserPasswordReserSerializer(serializers.Serializer):
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ["password", 'password2']
    
    def validate(self, attrs):
        try:
            password = attrs['password']
            password2 = attrs['password2']
            if password != password2:
                raise serializers.ValidationError("Password does not match")
            
            uid = self.context.get("uid")
            token = self.context.get("token")

            id = smart_str(urlsafe_base64_decode(uid))
            user_obj = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user_obj, token):
                raise serializers.ValidationError("Token Expired")
            user_obj.set_password(password)
            user_obj.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user_obj, token)
            raise serializers.ValidationError('Token is not Valid or Expired')
    
    