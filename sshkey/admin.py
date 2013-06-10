from django.contrib import admin
from sshkey.models import UserKey

class UserKeyAdmin(admin.ModelAdmin):
  search_fields = [
    'user__username',
  ]

admin.site.register(UserKey, UserKeyAdmin)
