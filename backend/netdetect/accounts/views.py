from django.shortcuts import render, redirect
from rest_framework.response import Response
from django.core.mail import EmailMessage
from django.http import JsonResponse
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework import generics
from django.contrib.auth import get_user_model
from django.conf import settings
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseNotFound
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User
from requests.exceptions import RequestException
import requests

from .serializers import *
from .forms import *

domain = 'http://' + settings.DOMAIN
host = settings.EMAIL_HOST_USER
User = get_user_model()

############################# Djoser Views ####################################

def activate_account(request, uid, token):
    """
    Activate a user account via uid and token.
    After activation, send a password reset email.
    """
    try:
        if uid and token:
            uid = str(uid)
            token = str(token)
            data = {'uid': uid, 'token': token}

            activation_url = f'{domain}/auth/users/activation/'
            response = requests.post(activation_url, data=data)

            if response.status_code == 204:  # Successful activation
                uid_decoded = urlsafe_base64_decode(uid).decode()
                user = User.objects.get(pk=uid_decoded)

                reset_password_url = f'{domain}/auth/users/reset_password/'
                reset_response = requests.post(reset_password_url, data={'email': user.email})

                if reset_response.status_code == 204:
                    message = 'Your account has been activated successfully. A password reset email has been sent.'
                else:
                    message = 'Account activated, but there was an issue sending the password reset email.'
            else:
                message = 'Invalid activation link.'
        else:
            message = 'Missing activation details.'

    except User.DoesNotExist:
        message = 'Invalid activation link: User does not exist.'
    except RequestException as e:
        message = 'There was an error activating your account. Please try again later.'
        print(f'Error during account activation: {e}')

    return render(request, 'activate.html', {'message': message})


def reset_email(request, uid, token):
    """
    View to reset the user's email address.
    """
    message = ''
    if request.method == 'POST':
        form = EmailResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            re_email = form.cleaned_data['re_email']

            if email == re_email:
                try:
                    if uid and token:
                        data = {'uid': uid, 'token': token, 'new_email': email, 're_new_email': re_email}

                        reset_email_url = f'{domain}/auth/users/reset_email_confirm/'
                        response = requests.post(reset_email_url, data=data)

                        if response.status_code == 204:
                            message = 'Email reset successfully.'
                        else:
                            response_data = response.json()
                            message = response_data.get('detail', 'Invalid activation link.')
                    else:
                        message = 'Invalid activation link.'

                except User.DoesNotExist:
                    message = 'Invalid activation link: User does not exist.'

            else:
                message = 'Emails do not match.'

        else:
            message = 'Form is not valid.'

    else:
        form = EmailResetForm()

    return render(request, 'reset_email.html', {'form': form, 'message': message})


def reset_password(request, uid, token):
    """
    View to reset the user's password.
    """
    message = ''
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']
            re_password = form.cleaned_data['re_password']

            if password == re_password:
                try:
                    if uid and token:
                        data = {'uid': uid, 'token': token, 'new_password': password, 're_new_password': re_password}

                        reset_password_url = f'{domain}/auth/users/reset_password_confirm/'
                        response = requests.post(reset_password_url, data=data)

                        if response.status_code == 204:
                            message = 'Password reset successfully.'
                            return redirect(settings.SITE_NAME)
                        else:
                            response_data = response.json()
                            message = response_data.get('detail', 'Invalid activation link.')

                    else:
                        message = 'Invalid activation link.'

                except User.DoesNotExist:
                    message = 'Invalid activation link: User does not exist.'
            else:
                message = 'Passwords do not match.'

        else:
            message = 'Form is not valid.'

    else:
        form = PasswordResetForm()

    return render(request, 'reset_password.html', {'form': form, 'message': message})


########################### Update User Info ######################################

class UpdateProfileView(generics.UpdateAPIView):
    """
    View to update user profile information.
    Only authenticated users can update their profile.
    """
    queryset = User.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = UserAccountSerializer
    
########################### Error Handling Views ##################################

def bad_request(request, exception):
    """
    Handle 400 Bad Request error.
    """
    return HttpResponseBadRequest(render(request, 'error.html'))


def page_not_found(request, exception):
    """
    Handle 404 Page Not Found error.
    """
    return HttpResponseNotFound(render(request, 'error.html'))


################################ contact views #####################################

def ContactMessageView(request):
        # Get data from the request
        name = request.data.get('name')
        email = request.data.get('email')
        subject = request.data.get('subject')
        message = request.data.get('message')

        # Validate the required fields
        if not name or not email or not subject or not message:
            return JsonResponse({"error": "All fields are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Prepare email
        email_subject = f"New Contact: {subject}"
        email_message = f"Message from {name} ({email}):\n\n{message}"
        reply_to = host 
        recipient_list = host
        from_email = email  # The user's email address for replies

        # Send the email
        email = EmailMessage(
            email_subject, 
            email_message, 
            from_email, 
            recipient_list, 
            reply_to=[reply_to]
        )

        try:
            email.send()
            return JsonResponse({"message": "Contact message submitted successfully."}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return JsonResponse({"error": f"Failed to send email: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)