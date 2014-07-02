# Copyright (c) 2014, Clemson University
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
# * Neither the name of the {organization} nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from django.http import HttpResponse, HttpResponseRedirect
from django.views.decorators.http import require_http_methods, require_GET
from django.shortcuts import get_object_or_404, render_to_response
from django.template import RequestContext
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.utils.http import is_safe_url
from django_sshkey import settings
from django_sshkey.models import UserKey
from django_sshkey.forms import UserKeyForm

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
        username=key.user.username,
        key_id=key.id,
      ) + ' '
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
    { 'userkey_list': userkey_list, 'allow_edit': settings.SSHKEY_ALLOW_EDIT },
    context_instance = RequestContext(request),
  )

@login_required
@require_http_methods(['GET', 'POST'])
def userkey_add(request):
  if request.method == 'POST':
    userkey = UserKey(user=request.user)
    userkey.META = request.META
    form = UserKeyForm(request.POST, instance=userkey)
    if form.is_valid():
      form.save()
      default_redirect = reverse('django_sshkey.views.userkey_list')
      url = request.GET.get('next', default_redirect)
      if not is_safe_url(url=url, host=request.get_host()):
        url = default_redirect
      message = 'SSH public key %s was added.' % userkey.name
      messages.success(request, message, fail_silently=True)
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
  if not settings.SSHKEY_ALLOW_EDIT:
    raise PermissionDenied
  userkey = get_object_or_404(UserKey, pk=pk)
  if userkey.user != request.user:
    raise PermissionDenied
  if request.method == 'POST':
    form = UserKeyForm(request.POST, instance=userkey)
    if form.is_valid():
      form.save()
      default_redirect = reverse('django_sshkey.views.userkey_list')
      url = request.GET.get('next', default_redirect)
      if not is_safe_url(url=url, host=request.get_host()):
        url = default_redirect
      message = 'SSH public key %s was saved.' % userkey.name
      messages.success(request, message, fail_silently=True)
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
  message = 'SSH public key %s was deleted.' % userkey.name
  messages.success(request, message, fail_silently=True)
  return HttpResponseRedirect(reverse('django_sshkey.views.userkey_list'))
