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
