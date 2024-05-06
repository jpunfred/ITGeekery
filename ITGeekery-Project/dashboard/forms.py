from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.contrib.auth.models import User
from .models import Profile

# signup.html Profile Creator
class SignUpForm(UserCreationForm):
    first_name = forms.CharField(max_length=30, required=False, help_text='(Optional)')
    last_name = forms.CharField(max_length=30, required=False, help_text='(Optional)')
    email = forms.EmailField(max_length=254, help_text='(Required)')
    company = forms.CharField(max_length=100)
    occupation = forms.CharField(max_length=100)
    keywords = forms.CharField(widget=forms.Textarea(attrs={'rows': 2}))

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2', 'company', 'occupation', 'keywords')
        error_messages = {
            'password_mismatch': 'Please enter the same password in both fields',
            'password_too_short': 'Please choose a password with at least 8 characters',
            'password_too_common': 'Please choose a more secure password',
            'password_entirely_numeric': 'Please include a mix of characters',
        }

    def save(self, commit=True):
        user = super(SignUpForm, self).save(commit=False)
        user.first_name = self.cleaned_data['first_name']
        user.last_name = self.cleaned_data['last_name']
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
            # Create and save the user's profile with additional details
            profile = Profile(
                user=user,
                company=self.cleaned_data['company'],
                occupation=self.cleaned_data['occupation'],
                keywords=self.cleaned_data['keywords']
            )
            profile.save()
        return user
#Update User Profile in account.html, excluding password
class ProfileUpdateForm(UserChangeForm):
    tickets_url = forms.URLField(required=False)
    device_management_url = forms.URLField(required=False)
    company_homepage_url = forms.URLField(required=False)
    keywords = forms.CharField(widget=forms.Textarea(attrs={'rows': 4}), required=False)

    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'tickets_url', 'device_management_url', 'company_homepage_url')
        exclude = ('password',)

    def __init__(self, *args, **kwargs):
        super(ProfileUpdateForm, self).__init__(*args, **kwargs)
        profile = self.instance.profile if hasattr(self.instance, 'profile') else None
        if 'password' in self.fields:
            del self.fields['password']
        if profile:
            self.fields['tickets_url'].initial = profile.tickets_url
            self.fields['device_management_url'].initial = profile.device_management_url
            self.fields['company_homepage_url'].initial = profile.company_homepage_url
            self.fields['keywords'].initial = profile.keywords

    def save(self, commit=True):
        user = super().save(commit=False)
        if commit:
            user.save()
            profile = user.profile
            profile.tickets_url = self.cleaned_data['tickets_url']
            profile.device_management_url = self.cleaned_data['device_management_url']
            profile.company_homepage_url = self.cleaned_data['company_homepage_url']
            profile.keywords = self.cleaned_data['keywords']
            profile.save()
        return user