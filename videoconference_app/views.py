import random
import string
from django.shortcuts import render, redirect

from videoconference_app.models import OTP
from .forms import RegisterForm
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages 
from django.core.mail import send_mail
from django.contrib.auth.models import User

# Create your views here.

def index(request):
    return render(request, 'index.html')

def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            form.save()
            return render(request, 'login.html', {'success': "Registration successful. Please login."})
        else:
            error_message = form.errors.as_text()
            return render(request, 'register.html', {'error': error_message})

    return render(request, 'register.html')


def login_view(request):
    if request.method=="POST":
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, username=email, password=password)
        if user is not None:
            login(request, user)
            return redirect("/dashboard")
        else:
            return render(request, 'login.html', {'error': "Invalid credentials. Please try again."})

    return render(request, 'login.html')

@login_required
def dashboard(request):
    return render(request, 'dashboard.html', {'name': request.user.first_name})

@login_required
def videocall(request):
    return render(request, 'videocall.html', {'name': request.user.first_name + " " + request.user.last_name})

@login_required
def logout_view(request):
    logout(request)
    return redirect("/login")

@login_required
def join_room(request):
    if request.method == 'POST':
        roomID = request.POST['roomID']
        return redirect("/meeting?roomID=" + roomID)
    return render(request, 'joinroom.html')


def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def password_reset_request(request):
    if request.method == 'POST':
        email = request.POST['email']
        try:
            user = User.objects.get(email=email)
            otp = generate_otp()
            OTP.objects.create(user=user, otp=otp)
            send_mail(
                'Password Reset OTP',
                f'Your OTP for password reset is {otp}',
                'your_email@example.com',
                [email],
                fail_silently=False,
            )
            request.session['email'] = email
            return redirect('password_reset_verify')
        except User.DoesNotExist:
            messages.error(request, 'No user found with this email')
    return render(request, 'password_reset_request.html')

def password_reset_verify(request):
    if request.method == 'POST':
        otp_input = request.POST['otp']
        email = request.session.get('email')
        try:
            user = User.objects.get(email=email)
            otp_record = OTP.objects.filter(user=user, otp=otp_input).order_by('-created_at').first()
            if otp_record and otp_record.is_valid():
                return redirect('password_reset_change')
            else:
                messages.error(request, 'Invalid or expired OTP')
        except User.DoesNotExist:
            messages.error(request, 'No user found with this email')
    return render(request, 'password_reset_verify.html')

def password_reset_change(request):
    if request.method == 'POST':
        new_password = request.POST['new_password']
        confirm_password = request.POST['confirm_password']
        if new_password == confirm_password:
            email = request.session.get('email')
            user = User.objects.get(email=email)
            user.set_password(new_password)
            user.save()
            messages.success(request, 'Password has been reset successfully')
            return redirect('login')
        else:
            messages.error(request, 'Passwords do not match')
    return render(request, 'password_reset_change.html')
