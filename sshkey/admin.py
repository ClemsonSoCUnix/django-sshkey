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

from django.contrib import admin
from sshkey.models import UserKey

class UserKeyAdmin(admin.ModelAdmin):
  list_display = [
    '__unicode__',
    'user',
    'name',
    'fingerprint',
  ]
  search_fields = [
    'user__username',
  ]
  readonly_fields = [
    'fingerprint',
  ]

admin.site.register(UserKey, UserKeyAdmin)
