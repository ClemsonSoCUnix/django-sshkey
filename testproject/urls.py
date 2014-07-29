try:
  from django.conf.urls import patterns, include, url
except ImportError:
  from django.conf.urls.defaults import patterns, include, url

from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
  url(r'^', include('django_sshkey.urls')),
  url(r'^admin/', include(admin.site.urls)),
)
