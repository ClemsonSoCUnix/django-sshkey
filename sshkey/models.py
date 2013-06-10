from django.db import models
from django.dispatch import receiver
from django.db.models.signals import pre_save
from django.contrib.auth.models import User
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

@receiver(pre_save, sender=UserKey, dispatch_uid=__name__ + '.set_fingerprint')
def set_fingerprint(sender, instance, **kwargs):
  instance.fingerprint = sshkey_fingerprint(instance.key)
