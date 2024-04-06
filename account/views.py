from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import *
from django.contrib.auth import authenticate
from .renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

# Create your views here.

# generate token manually
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserRegistrationSerializer(data = request.data)
        if serializer.is_valid():
            user_obj = serializer.save()
            token = get_tokens_for_user(user_obj)
            return Response({"token": token  , "msg":"Registration Successfull"}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserLoginView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserLoginSerializer(data = request.data)
        if serializer.is_valid():
            email = serializer.data.get('email')
            password = serializer.data['password']
            user_obj = authenticate(email=email, password=password)
            if user_obj is not None:
                token = get_tokens_for_user(user_obj)
                return Response({"token":token , "msg":"Login Successfull"}, status=status.HTTP_200_OK)
            else:
                return Response({"errors":{"non_field_errors":["Email or Password is Wrong"]}}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)
            


class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]        
    
    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(data = request.data, context={"user": request.user})
        if serializer.is_valid():
            return Response({ "msg":"Password changed Successfull"}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = SendPasswordResetViewSerializer(data = request.data)
        if serializer.is_valid():
            return Response({ "msg":"Password Reset Link is sent to email"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
class UserPasswordReserView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, uid, token, format=None):
        context = {"uid":uid, "token":token}
        serializer = UserPasswordReserSerializer(data = request.data, context=context)
        if serializer.is_valid():
            return Response({ "msg":"Your Password has been Reset"}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




