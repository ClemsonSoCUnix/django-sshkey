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
from django.core.exceptions import ValidationError
from uuid import uuid4
from ...models import UserKey


class Command(BaseCommand):
  help = 'Import SSH public key on behalf of a user'

  def add_arguments(self, parser):
    parser.add_argument('username')
    parser.add_argument('key_path', nargs='+')
    parser.add_argument('-n', '--name',
                        help='Set the name of the key; by default the comment '
                             'is used')
    parser.add_argument('-p', '--prefix',
                        help='Prefix to use during name conflict resolution; '
                             'the default uses the key name')
    parser.add_argument('-a', '--auto-resolve', action='store_true',
                        help='Try to resolve conflicts using UUIDs')

  def handle(self, *args, **options):
    username = options['username']
    keys = options['key_path']
    name = options['name']

    try:
      user = User.objects.get(username=username)
    except User.DoesNotExist:
      raise CommandError('No such user: %s' % username)

    for key in keys:
      with open(key) as fp:
        key_data = fp.read()

      key_model = UserKey(user=user, key=key_data)
      if name is not None:
        key_model.name = name

      try:
        self._clean_key(key_model, options)
      except:
        self.stdout.write('Failed to import %s' % key)
        raise
      else:
        key_model.save()
        self.stdout.write('Imported %s as %s' % (key, key_model.name))

  def _clean_key(self, key, options):
    '''
    Try to save the key with a unique name if requested.
    '''
    auto_resolve = options['auto_resolve']
    auto_prefix = options['prefix']
    uuid = uuid4().hex[:7]
    try:
      key.full_clean()
    except ValidationError as e:
      if 'name' in e.message_dict and auto_resolve:
        prefix = auto_prefix if auto_prefix is not None else key.name
        key.name = '-'.join([prefix, uuid])
        key.full_clean()
      else:
        raise
