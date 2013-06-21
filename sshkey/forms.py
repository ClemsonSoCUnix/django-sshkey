from django import forms
from sshkey.models import UserKey

class UserKeyForm(forms.ModelForm):
  class Meta:
    model = UserKey
    fields = ['name', 'key']
