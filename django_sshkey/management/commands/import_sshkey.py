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
