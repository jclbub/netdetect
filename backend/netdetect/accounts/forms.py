from django import forms

class PasswordResetForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'inputContainer', 'name': 'password', 'placeholder': 'Enter your password'}))
    re_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'inputContainer', 'name': 're_password', 'placeholder': 'Confirm your password'}))

class EmailResetForm(forms.Form):
    email = forms.CharField(widget=forms.EmailInput(attrs={'class': 'inputContainer', 'name': 'email', 'placeholder': 'Enter your new email'}))
    re_email = forms.CharField(widget=forms.EmailInput(attrs={'class': 'inputContainer', 'name': 're_email', 'placeholder': 'Confirm your new email'}))
