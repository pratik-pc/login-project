from base64 import urlsafe_b64encode
from lib2to3.pgen2.tokenize import generate_tokens
from unicodedata import name
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from my_clone import settings
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_text
from . tokens import generate_token

# Create your views here.
def home(request):
    return render(request, "authentication/index.html")

def signup(request):
    if request.method == "POST":
        name = request.POST.get('name')
        email = request.POST.get('email')
        pass1 = request.POST.get('password1')
        pass2 = request.POST.get('password2')

        if User.objects.filter(email=email):
            messages.error(request, "Email already registered!")
            return redirect('signup')
        
        if pass1 != pass2:
            messages.error(request, "Passwords didn't match")
        

        myuser = User.objects.create_user(name, email, pass1)
        myuser.is_active = False
        myuser.save()

        messages.success(request, "Your account has been created successfully")

        #Email
        subject = "Welcome to clone"
        message = "Hello" + myuser.name + ". \n" + "Welcome to clone"
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True)

        #Email confirmation
        current_site = get_current_site(request)
        email_subject = "Confirm your email"
        message2 = render_to_string('email_confirmation.html'),{
            'name': myuser.name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser),
        }


        return redirect('signin')
    return render(request, "authentication/signup.html")

def signin(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        user = authenticate(email=email, password=password)

        if user is not None:
            login(request, user)
            name = user.name
            return render(request, "authentication/index.html", {'name':name})
        
        else:
            messages.error(request, "Bad credentials!")
            return redirect('signin')

    return render(request, "authentication/signin.html")


def signout(request):
    logout(request)
    messages.success(request, "Logged out successfully!")
    return redirect('home')