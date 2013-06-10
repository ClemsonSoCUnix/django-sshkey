from django.http import HttpResponse
from django.conf import settings
from sshkey.models import UserKey

def lookup(request):
  try:
    fingerprint = request.GET['fingerprint']
    keys = UserKey.objects.filter(fingerprint=fingerprint)
  except KeyError:
    try:
      username = request.GET['username']
      keys = UserKey.objects.filter(user__username=username)
    except KeyError:
      keys = UserKey.objects.iterator()
  response = ''
  for key in keys:
    try:
      options = 'command="%s" ' % (
        settings.SSHKEY_AUTHORIZED_KEYS_COMMAND
          .format(username=key.user.username)
          .replace('"', r'\"')
      )
    except AttributeError:
      options = ''
    response += options + key.key + '\n'
  return HttpResponse(response, mimetype='text/plain')
