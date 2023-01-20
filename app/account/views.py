# References
# doc: https://docs.djangoproject.com/en/4.1/topics/auth/default/
# is_valid: https://stackoverflow.com/questions/45824046/djangos-authentication-form-is-always-not-valid

# TODO:
# - [ ] Doc string
# - [ ] study form parameters

from math import floor
from random import random

from django.shortcuts import redirect, render
from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.core.mail import send_mail
from django.contrib.auth.decorators import login_required

from .forms import MyUser, NewUserForm, OTPForm


def otp_request(request):
    if 'is_valid' not in request.session:
        return redirect('/')
    if request.session['is_valid'] is not True:
        return redirect('/')

    if request.method == 'POST':
        print("test")
        otp = request.POST['otp']

        try:
            if request.session['tmp_OTP'] == otp:

                # User's credentials
                username = request.session['user_email']
                password = request.session['user_password']

                user = authenticate(
                    request, username=username, password=password)

                # Log In
                if user is None:
                    try:
                        MyUser.objects.create_user(
                            email=request.session['user_email'],
                            password=request.session['user_password'],
                        )
                    except:
                        messages.error(request, "Something wrong with signup.")

                    user = authenticate(
                        request, username=username, password=password)

                # Go to home page
                request.session.clear()
                login(request, user)
                return redirect('/')

            else:
                messages.error(
                    request, "Incorrect OTP.")

        except:
            messages.error(
                request, "Encountered an error while validating OTP.")

    send_otp(request)
    form = OTPForm()
    return render(request, 'account/otp.html', {'form': form})


def send_otp(request):
    if 'is_valid' not in request.session:
        return redirect('/')
    if request.session['is_valid'] is not True:
        return redirect('/')

    email = request.session['user_email']

    # Generate OTP
    string = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    otp = ""
    length = len(string)
    for _ in range(6):
        otp = otp + string[floor(random() * length)]

    print("OTP Code: " + otp)

    # Remember the OTP Code
    request.session['tmp_OTP'] = otp

    # Send mail
    subject = 'SWE: One Time Password'
    message = f'Hi {email}, your otp is {otp}.'
    email_from = 'Jhaime Jose Cando'
    recipient_list = [email, ]
    try:
        send_mail(subject, message, email_from, recipient_list)
        messages.success(
            request, "The OTP has been sent to your email.")
    except:
        messages.error(
            request, "Encountered an error while sending a mail.")

    return redirect('account:otp')


def signup_request(request):

    request.session.clear()

    if request.method == "POST":
        form = NewUserForm(request.POST)
        if form.is_valid():
            request.session['user_email'] = form.cleaned_data['email']
            request.session['user_password'] = form.cleaned_data['password1']
            request.session['is_valid'] = True
            return redirect('account:otp')

        else:
            messages.error(
                request, "Unsuccessful registration. Either email is already taken or password doesn't matched")

    form = NewUserForm()
    return render(request, "account/signup.html", {"form": form})


def login_request(request):

    request.session.clear()

    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            username = request.POST['username']
            password = request.POST['password']
            user = authenticate(request, username=username, password=password)

            if user is not None:
                request.session['user_email'] = username
                request.session['user_password'] = password
                request.session['is_valid'] = True
                return redirect('account:otp')
            else:
                messages.error(request, "Invalid username or password.")

        else:
            messages.error(request, "Invalid username or password.")

    form = AuthenticationForm()
    return render(request, "account/login.html", {"form": form})


@login_required(login_url='/account/login/')
def logout_request(request):
    logout(request)
    return redirect('/')
