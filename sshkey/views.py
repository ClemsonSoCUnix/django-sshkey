from django.http import HttpResponse, HttpResponseRedirect
from django.views.decorators.http import require_http_methods, require_GET
from django.shortcuts import get_object_or_404, render_to_response
from django.template import RequestContext
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.utils.http import is_safe_url
from sshkey import settings
from sshkey.models import UserKey
from sshkey.forms import UserKeyForm

@require_GET
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
    if settings.SSHKEY_AUTHORIZED_KEYS_OPTIONS:
      options = settings.SSHKEY_AUTHORIZED_KEYS_OPTIONS.format(
        username=key.user.username) + ' '
    elif settings.SSHKEY_AUTHORIZED_KEYS_COMMAND:
      options = 'command="%s" ' % (
        settings.SSHKEY_AUTHORIZED_KEYS_COMMAND
          .format(username=key.user.username)
          .replace('"', r'\"')
      )
    else:
      options = ''
    response += options + key.key + '\n'
  return HttpResponse(response, mimetype='text/plain')

@login_required
@require_GET
def userkey_list(request):
  userkey_list = UserKey.objects.filter(user=request.user)
  return render_to_response(
    'sshkey/userkey_list.html',
    { 'userkey_list': userkey_list },
    context_instance = RequestContext(request),
  )

@login_required
@require_http_methods(['GET', 'POST'])
def userkey_add(request):
  if request.method == 'POST':
    userkey = UserKey(user=request.user)
    form = UserKeyForm(request.POST, instance=userkey)
    if form.is_valid():
      form.save()
      default_redirect = reverse('sshkey.views.userkey_list')
      url = request.GET.get('next', default_redirect)
      if not is_safe_url(url=url, host=request.get_host()):
        url = default_redirect
      return HttpResponseRedirect(url)
  else:
    form = UserKeyForm()
  return render_to_response(
    'sshkey/userkey_detail.html',
    { 'form': form, 'action': 'add' },
    context_instance = RequestContext(request),
  )

@login_required
@require_http_methods(['GET', 'POST'])
def userkey_edit(request, pk):
  userkey = get_object_or_404(UserKey, pk=pk)
  if userkey.user != request.user:
    raise PermissionDenied
  if request.method == 'POST':
    form = UserKeyForm(request.POST, instance=userkey)
    if form.is_valid():
      form.save()
      default_redirect = reverse('sshkey.views.userkey_list')
      url = request.GET.get('next', default_redirect)
      if not is_safe_url(url=url, host=request.get_host()):
        url = default_redirect
      return HttpResponseRedirect(url)
  else:
    form = UserKeyForm(instance=userkey)
  return render_to_response(
    'sshkey/userkey_detail.html',
    { 'form': form, 'action': 'edit' },
    context_instance = RequestContext(request),
  )

@login_required
@require_GET
def userkey_delete(request, pk):
  userkey = get_object_or_404(UserKey, pk=pk)
  if userkey.user != request.user:
    raise PermissionDenied
  userkey.delete()
  return HttpResponseRedirect(reverse('sshkey.views.userkey_list'))
