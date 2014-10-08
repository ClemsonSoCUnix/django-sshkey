# Copyright (c) 2014, Clemson University
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the {organization} nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from django import forms
from django_sshkey.models import Key, UserKey
from django_sshkey.util import pubkey_parse

class ApplicationKeyForm(forms.ModelForm):
  key = forms.CharField(max_length=2000, required=True)

  def clean(self):
    cleaned_data = self.cleaned_data
    if 'key' in cleaned_data:
      key = cleaned_data['key'] = Key(key=cleaned_data['key'])
      key.full_clean()
    return cleaned_data

  def save(self, commit=True):
    instance = super(ApplicationKeyForm, self).save(commit=False)
    if commit:
      basekey = self.cleaned_data['key']
      basekey.save()
      instance.basekey = basekey
      instance.save()
    return instance

class NamedKeyForm(ApplicationKeyForm):
  def clean(self):
    cleaned_data = super(NamedKeyForm, self).clean()
    if 'key' in cleaned_data and not cleaned_data.get('name'):
      pubkey = pubkey_parse(cleaned_data['key'].key)
      if not pubkey.comment:
        raise ValidationError('Name or key comment required')
      cleaned_data['name'] = pubkey.comment
    return cleaned_data

class UserKeyForm(NamedKeyForm):

  class Meta:
    model = UserKey
    fields = ['name', 'key']
    exclude = ['basekey']
    widgets = {
      'key': forms.Textarea(attrs={
        'cols': 72,
        'rows': 15,
        'placeholder': "Paste in the contents of your public key file here",
      }),
      'name': forms.TextInput(attrs={
        'size': 50,
        'placeholder': "username@hostname, or leave blank to use key comment",
      })
    }
