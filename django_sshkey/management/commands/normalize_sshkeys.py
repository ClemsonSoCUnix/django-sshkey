# Copyright (c) 2014-2016, Clemson University
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
# * Neither the name of Clemson University nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from ...models import UserKey


class Command(BaseCommand):
  help = 'Recalculate SSH key data such that all keys are uniformly formatted'

  def add_arguments(self, parser):
    parser.add_argument('username', nargs='?',
                        help='If given, normalize keys owned by this user')
    parser.add_argument('key_name', nargs='?',
                        help='If given, normalize a single key by its name')

  def handle(self, *args, **options):
    username = options['username']
    key_name = options['key_name']

    if username is not None:
      try:
        user = User.objects.get(username=username)
      except User.DoesNotExist:
        raise CommandError('No such user: %s' % username)
    else:
      user = None

    qs = UserKey.objects.all()
    if user is not None:
      qs = qs.filter(user=user)
    if key_name is not None:
      qs = qs.filter(name=key_name)

    if not qs:
      raise CommandError('No keys matched')

    count = qs.count()
    for key in qs:
      key.full_clean()
      key.save()
    if count == 1:
      self.stdout.write('Normalized `%s`' % key)
    else:
      self.stdout.write('Normalized %d key(s)' % count)
