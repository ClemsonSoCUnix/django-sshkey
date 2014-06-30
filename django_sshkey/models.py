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

from django.db import models
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django_sshkey.util import SSHKeyFormatError, key_parse

def wrap(text, width, end=None):
  n = 0
  t = ''
  if end is None:
    while n < len(text):
      m = n + width
      t += text[n:m]
      if len(text) <= m:
        return t
      t += '\n'
      n = m
  else:
    while n < len(text):
      m = n + width
      if len(text) <= m:
        return t + text[n:m]
      m -= len(end)
      t += text[n:m] + end + '\n'
      n = m
  return t

class UserKey(models.Model):
  user = models.ForeignKey(User, db_index=True)
  name = models.CharField(max_length=50, blank=True)
  key = models.TextField(max_length=2000)
  fingerprint = models.CharField(max_length=47, blank=True, db_index=True)
  created = models.DateTimeField(auto_now_add=True, null=True)
  last_modified = models.DateTimeField(auto_now=True, null=True)

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

  def clean(self):
    try:
      info = key_parse(self.key)
      self.fingerprint = info.fingerprint
      if info.comment:
        self.key = "%s %s %s" % (info.type.decode(), info.b64key.decode(), info.comment)
      else:
        self.key = "%s %s" % (info.type.decode(), info.b64key.decode())
    except SSHKeyFormatError as e:
      raise ValidationError(str(e))
    if not self.name:
      if not info.comment:
        raise ValidationError('Name or key comment required')
      self.name = info.comment

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

  def export_openssh(self):
    return self.key.encode('utf-8')

  def export_rfc4716(self):
    info = key_parse(self.key)
    out = b'---- BEGIN SSH2 PUBLIC KEY ----\n'
    if info.comment:
      comment = 'Comment: "%s"' % info.comment
      out += wrap(comment, 72, '\\').encode('ascii') + b'\n'
    out += wrap(info.b64key, 72).encode('ascii') + b'\n'
    out += b'---- END SSH2 PUBLIC KEY ----'
    return out
