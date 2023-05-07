from multiprocessing import AuthenticationError
from pyexpat.errors import messages
from telnetlib import AUTHENTICATION
from django.shortcuts import redirect, render, redirect, HttpResponse
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from Main.settings import AUTH_PASSWORD_VALIDATORS
# Create your views here.


def index(request):
    return render(request, 'index.html')


def login(request):
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']
        user = AuthenticationError.authenticate(
            username=username, password=password)
        if user is not None:
            AUTHENTICATION.login(request, user)
            return redirect('/')
        else:
            messages.info(request, "invalid login")
            return redirect('login')
    else:
        # User is authenticated
        return render(request, "login.html")


def signup(request):
    if request.method == "POST":
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        if User.objects.filter(username=username).exists():
            messages.info(request, "username already exists")
            return redirect('register')
        elif User.objects.filter(email=email).exists():
            messages.info(request, "email taken")
            return redirect('register')
        else:
            user = User.objects.create_user(
                username=username, email=email, password=password)
            user.save()
        return redirect('/')

    return render(request, 'signup.html')
