from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from sshkey.models import sshkey_fingerprint, UserKey
import base64
import hashlib
import sys

class Command(BaseCommand):
  args = '[<username>]'

  def handle(self, *args, **options):
    if len(args) == 0:
      line = sys.stdin.readline()
      if not line:
        raise CommandError('no input given')
      fingerprint = sshkey_fingerprint(line)
      keys = UserKey.objects.filter(fingerprint=fingerprint)
    elif len(args) == 1:
      keys = UserKey.objects.filter(user__username=args[0])
    else:
      raise CommandError('invalid number of arguments')
    status = 1
    for key in keys:
      status = 0
      try:
        options = 'command="%s" ' % (
          settings.SSHKEY_AUTHORIZED_KEYS_COMMAND.format(username=key.user.username).replace('"', r'\"')
        )
      except AttributeError:
        options = ''
      print(options + key.key)
    return status
