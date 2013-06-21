from django.db import models
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from sshkey.util import sshkey_fingerprint

class UserKey(models.Model):
  user = models.ForeignKey(User, db_index=True)
  name = models.CharField(max_length=50)
  key = models.TextField(max_length=2000)
  fingerprint = models.CharField(max_length=47, blank=True, db_index=True)

  class Meta:
    unique_together = [
      ('user', 'name'),
    ]

  def __unicode__(self):
    return unicode(self.user) + u': ' + self.name

  def clean(self):
    try:
      self.fingerprint = sshkey_fingerprint(self.key)
    except Exception, e:
      raise ValidationError('Not a valid SSH key: ' + str(e))

  def validate_unique(self, exclude=None):
    if self.pk is None:
      objects = type(self).objects
    else:
      objects = type(self).objects.exclude(pk=self.pk)
    if exclude is None or 'name' not in exclude:
      if objects.filter(user=self.user, name=self.name).count():
        raise ValidationError({'name': ['A key with this name already exists']})
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
