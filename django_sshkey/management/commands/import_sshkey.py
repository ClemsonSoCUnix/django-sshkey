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
    parser.add_argument('-n', '--name')

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

      try:
        key_model = UserKey(user=user, key=key_data)
        self._clean_key(key_model, name)
        key_model.save()
      except:
        self.stdout.write('Failed to import %s' % key)
        raise
      else:
        self.stdout.write('Imported %s as %s' % (key, key_model.name))

  def _clean_key(self, key, name):
    '''
    Try to save the key with a unique name.
    '''
    uuid = uuid4().hex[:7]
    for i in range(2):
      try:
        key.full_clean()
      except ValidationError as e:
        if 'name' in e.message_dict and name is not None:
          key.name = '-'.join([name, uuid])
        else:
          raise
