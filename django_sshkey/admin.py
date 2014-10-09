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

from django.contrib import admin
from django.core.urlresolvers import reverse
from django_sshkey.models import UserKey, Key

class KeyAdmin(admin.ModelAdmin):
  list_display = [
    '__unicode__',
    'created',
    'last_modified',
    'last_used',
  ]
  readonly_fields = [
    'fingerprint',
    'created',
    'last_modified',
    'last_used',
  ]
  search_fields = [
    'fingerprint',
  ]

class ApplicationKeyAdmin(KeyAdmin):
  list_display = [
    '__unicode__',
    'basekey',
    'created',
    'last_modified',
    'last_used',
  ]
  search_fields = []  # would be quite slow to search on fingerprint
  readonly_fields = [
    'created',
    'last_modified',
    'last_used',
    'basekey_link',
  ]

  def basekey_link(self, obj):
    url = reverse('admin:django_sshkey_key_change', args=(obj.basekey.id,))
    return '<a href="%s">%s</a>' % (url, obj.basekey)
  basekey_link.allow_tags = True

class NamedKeyAdmin(ApplicationKeyAdmin):
  search_fields = [
    'name',
  ]

class UserKeyAdmin(NamedKeyAdmin):
  list_display = [
    '__unicode__',
    'user',
    'basekey',
    'created',
    'last_modified',
    'last_used',
  ]
  search_fields = [
    'name',
    'user__username',
  ]

admin.site.register(Key, KeyAdmin)
admin.site.register(UserKey, UserKeyAdmin)
