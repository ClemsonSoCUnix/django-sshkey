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
