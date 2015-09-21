# Copyright (c) 2014-2015, Clemson University
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

from django.db import models
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db.models.signals import pre_save
from django.dispatch import receiver
try:
  from django.utils.timezone import now
except ImportError:
  import datetime
  now = datetime.datetime.now
from django_sshkey.util import PublicKeyParseError, pubkey_parse
from django_sshkey import settings

class UserKey(models.Model):
  user = models.ForeignKey(User, db_index=True)
  name = models.CharField(max_length=50, blank=True)
  key = models.TextField(max_length=2000)
  fingerprint = models.CharField(max_length=47, blank=True, db_index=True)
  created = models.DateTimeField(auto_now_add=True, null=True)
  last_modified = models.DateTimeField(null=True)
  last_used = models.DateTimeField(null=True)

  class Meta:
    db_table = 'sshkey_userkey'
    unique_together = [
      ('user', 'name'),
    ]

  def __unicode__(self):
    return unicode(self.user) + u': ' + self.name

  def clean_fields(self, exclude=None):
    if not exclude or 'key' not in exclude:
      self.key = self.key.strip()
      if not self.key:
        raise ValidationError({'key': ["This field is required."]})

  def clean(self):
    self.key = self.key.strip()
    if not self.key:
      return
    try:
      pubkey = pubkey_parse(self.key)
    except PublicKeyParseError as e:
      raise ValidationError(str(e))
    self.key = pubkey.format_openssh()
    self.fingerprint = pubkey.fingerprint()
    if not self.name:
      if not pubkey.comment:
        raise ValidationError('Name or key comment required')
      self.name = pubkey.comment

  def validate_unique(self, exclude=None):
    if self.pk is None:
      objects = type(self).objects
    else:
      objects = type(self).objects.exclude(pk=self.pk)
    if exclude is None or 'name' not in exclude:
      if objects.filter(user=self.user, name=self.name).count():
        message = 'You already have a key with that name'
        raise ValidationError({'name': [message]})
    if exclude is None or 'key' not in exclude:
      try:
        other = objects.get(fingerprint=self.fingerprint, key=self.key)
        if self.user == other.user:
          message = 'You already have that key on file (%s)' % other.name
        else:
          message = 'Somebody else already has that key on file'
        raise ValidationError({'key': [message]})
      except type(self).DoesNotExist:
        pass

  def export(self, format='RFC4716'):
    pubkey = pubkey_parse(self.key)
    f = format.upper()
    if f == 'RFC4716':
      return pubkey.format_rfc4716()
    if f == 'PEM':
      return pubkey.format_pem()
    raise ValueError("Invalid format")

  def save(self, *args, **kwargs):
    if kwargs.pop('update_last_modified', True):
      self.last_modified = now()
    super(UserKey, self).save(*args, **kwargs)

  def touch(self):
    self.last_used = now()
    self.save(update_last_modified=False)

@receiver(pre_save, sender=UserKey)
def send_email_add_key(sender, instance, **kwargs):
  if not settings.SSHKEY_EMAIL_ADD_KEY or instance.pk:
    return
  from django.template.loader import render_to_string
  from django.core.mail import EmailMultiAlternatives
  from django.core.urlresolvers import reverse
  context_dict = {
    'key': instance,
    'subject': settings.SSHKEY_EMAIL_ADD_KEY_SUBJECT,
  }
  request = getattr(instance, 'request', None)
  if request:
    context_dict['request'] = request
    context_dict['userkey_list_uri'] = request.build_absolute_uri(reverse('django_sshkey.views.userkey_list'))
  text_content = render_to_string('sshkey/add_key.txt', context_dict)
  msg = EmailMultiAlternatives(
    settings.SSHKEY_EMAIL_ADD_KEY_SUBJECT,
    text_content,
    settings.SSHKEY_FROM_EMAIL,
    [instance.user.email],
  )
  if settings.SSHKEY_SEND_HTML_EMAIL:
    html_content = render_to_string('sshkey/add_key.html', context_dict)
    msg.attach_alternative(html_content, 'text/html')
  msg.send()
