from django.conf import settings
from django.shortcuts import render, HttpResponse
from django.shortcuts import get_object_or_404
from django.http.response import JsonResponse

from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAdminUser, IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser

from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.core.mail import send_mail, EmailMessage

from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import User, Student, Teacher, ClassRoom, Subject, TeacherFile
from .serializers import PasswordResetSerializer, UserSerializer, StudentSerializer, TeacherSerializer, ClassroomSerializer, SubjectSerializer, TeacherFileSerializer,ForgotPasswordSerializer

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        token['username'] = user.username
        token['id'] = user.id
        token['is_admin'] = user.is_admin
        token['is_student'] = user.is_student
        token['is_teacher'] = user.is_teacher

        return token
        
class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer
   
class UserRegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

def send_password_set_email(user):
    email = user.email
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    current_site = 'http://127.0.0.1:8000/'
    mail_subject = "Reset your password"
    link = f'http://localhost:3000/create-new-password/?uid={uid}&token={token}'

    context = {
        "link": link,
        "username": user.username
    }
    subject = "Password reset email"
    html_body = render_to_string("email/set_password.html", context)
    email_message = EmailMessage(
        subject=subject,
        body=html_body,
        from_email=settings.EMAIL_HOST_USER,
        to=[email]
    )
    email_message.content_subtype = 'html'
    email_message.send(fail_silently=False)
class ForgotPasswordView(generics.GenericAPIView):
    serializer_class = ForgotPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"email": "User with this email does not exist."}, status=status.HTTP_400_BAD_REQUEST)
        
        send_password_set_email(user)
        return Response({"detail": "Password reset email has been sent."}, status=status.HTTP_200_OK)


class StudentRegisterView(generics.CreateAPIView):
    queryset = Student.objects.all()
    serializer_class = StudentSerializer
    permission_classes = [IsAdminUser, IsAuthenticated]

    def perform_create(self, serializer):
        student = serializer.save(is_student=True)
        print(student, 'student')
        print(student.email, 'email')
        send_password_set_email(student)

class TeacherRegisterView(generics.CreateAPIView):
    permission_classes = [IsAdminUser, IsAuthenticated]
    queryset = Teacher.objects.all()
    serializer_class = TeacherSerializer

    def perform_create(self, serializer):
        teacher = serializer.save(is_teacher=True)
        send_password_set_email(teacher)

class PasswordResetConfirmView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            user = serializer.save()
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"detail": "Password has been reset successfully."}, status=status.HTTP_200_OK)

class StudentListUpdateView(generics.RetrieveUpdateDestroyAPIView):
    # permission_classes = [IsAuthenticated]
    serializer_class = StudentSerializer

    def get_object(self):
        pk = self.kwargs.get('pk')
        return get_object_or_404(Student, id=pk)

    # def put(self,request,*args, **kwargs):
    #     instance = self.get_object()
    #     data = request.data.copy()
    #     password = data.get('password')
    #     if password:
    #         instance.set_password(password)
    #         instance.save()
    #         data.pop('password',None)
    #     serializer = self.get_serializer(instance,data = request.data,partial = True)
    #     if serializer.is_valid():
    #         serializer.save()
    #         return Response(serializer.data)
    #     else:
    #         print(serializer.errors)
    #         return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)


class StudentList(generics.ListAPIView):
    queryset = Student.objects.all()
    serializer_class = StudentSerializer
    permission_classes = [IsAdminUser, IsAuthenticated]


class SubjectListCreateView(generics.ListCreateAPIView):
    queryset = Subject.objects.all()
    serializer_class = SubjectSerializer

class SubjectUpdateView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Subject.objects.all()
    serializer_class = SubjectSerializer

class TeacherList(generics.ListAPIView):
    queryset = Teacher.objects.all()
    serializer_class = TeacherSerializer
    permission_classes = [IsAuthenticated]

class TeacherView(generics.RetrieveUpdateAPIView):
    serializer_class = TeacherSerializer
    permission_classes = [AllowAny]

    def get_object(self):
        pk = self.kwargs.get('pk')
        return get_object_or_404(Teacher, id=pk)
    



class TeacherFileUploadView(APIView):
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, *args, **kwargs):
        teacher_id = request.data.get('teacher_id')
        teacher = Teacher.objects.get(id=teacher_id)
        files = request.FILES.getlist('files')
        file_objects = []
        for file in files:
            file_obj = TeacherFile(teacher=teacher, file=file)
            file_obj.save()
            file_objects.append(file_obj)
        serializer = TeacherFileSerializer(file_objects, many=True)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class TeacherDetailView(APIView):
    def get(self, request, teacher_id, *args, **kwargs):
        teacher = Teacher.objects.get(id=teacher_id)
        serializer = TeacherSerializer(teacher)
        return Response(serializer.data, status=status.HTTP_200_OK)



class BlockUserView(APIView):
    # permission_classes = [IsAdminUser]

    def post(self, request, pk):
        try:
            user = User.objects.get(pk=pk)
            user.is_active = False
            user.save()
            serializer = UserSerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


class UnBlockUserView(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request, pk):
        try:
            user = User.objects.get(pk=pk)
            user.is_active = True
            user.save()
            serializer = UserSerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        
class ClassRoomAPIView(generics.ListCreateAPIView):
    queryset = ClassRoom.objects.all()
    serializer_class = ClassroomSerializer
    # # permission_classes = [IsAdminUser, IsAuthenticated]


class ClassUpdateView(generics.RetrieveUpdateDestroyAPIView):
    queryset = ClassRoom.objects.all()
    serializer_class = ClassroomSerializer
    
    # def list(self, request):
    #     queryset = self.get_queryset()
    #     serializer = ClassroomSerializer(queryset, many=True)
    #     return Response(serializer.data)
    
    # def get(self, request):
    #     class_obj = ClassRoom.objects.all()
    #     serializer = ClassroomSerializer(class_obj, many=True)
    #     return Response(serializer.data)
    


# class TeacherListUpdateView(generics.RetrieveUpdateDestroyAPIView):
#     serializer_class = TeacherSerializer
#     def get_object(self):
#         pk = self.kwargs.get('pk')
#         return get_object_or_404(Teacher, user_id=pk)

#     def put(self,request,*args, **kwargs):
#         instance = self.get_object()
#         # data = request.data.copy()
#         # password = data.get('password')
#         # if password:
#         #     instance.set_password(password)
#         #     instance.save()
#         #     data.pop('password',None)
#         print(request.data)
#         serializer = self.get_serializer(instance, data=request.data, partial = True)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data)
#         else:
#             print(serializer.errors)
#             return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST) 