# Copyright 2013 Scott Duckworth
#
# This file is part of django-sshkey.
#
# django-sshkey is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# django-sshkey is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with django-sshkey.  If not, see <http://www.gnu.org/licenses/>.

from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from django_sshkey.models import sshkey_fingerprint, UserKey
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
