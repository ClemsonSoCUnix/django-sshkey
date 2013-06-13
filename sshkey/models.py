from django.db import models
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from sshkey.util import sshkey_fingerprint

class UserKey(models.Model):
  user = models.ForeignKey(User, db_index=True)
  name = models.CharField(max_length=50)
  key = models.TextField(max_length=2000)
  fingerprint = models.CharField(max_length=47, unique=True, blank=True, db_index=True)

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
