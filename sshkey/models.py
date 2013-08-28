from django.db import models
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
import base64
import hashlib
import re

sshkey_re = re.compile(r'(?P<type>[\w-]+)\s+(?P<b64key>\S+)(?:\s+(?P<comment>\S+))?$')

def sshkey_fingerprint(b64key):
  key = base64.b64decode(b64key)
  fp_plain = hashlib.md5(key).hexdigest()
  return ':'.join(a+b for a,b in zip(fp_plain[::2], fp_plain[1::2]))

class UserKey(models.Model):
  user = models.ForeignKey(User, db_index=True)
  name = models.CharField(max_length=50, blank=True)
  key = models.TextField(max_length=2000)
  fingerprint = models.CharField(max_length=47, blank=True, db_index=True)

  class Meta:
    unique_together = [
      ('user', 'name'),
    ]

  def __unicode__(self):
    return unicode(self.user) + u': ' + self.name

  def clean_fields(self, exclude=None):
    if not exclude or 'key' not in exclude:
      self.key = self.key.strip()

  def clean(self):
    m = sshkey_re.match(self.key)
    errmsg = 'Key is not a valid SSH protocol 2 base64-encoded key'
    if not m:
      raise ValidationError(errmsg)
    try:
      self.fingerprint = sshkey_fingerprint(m.group('b64key'))
    except TypeError:
      raise ValidationError(errmsg)
    if not self.name:
      comment = m.group('comment')
      if not comment:
        raise ValidationError('Name or key comment required')
      self.name = comment

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
