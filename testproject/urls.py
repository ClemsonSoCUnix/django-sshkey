from django.conf.urls.defaults import patterns, include, url
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
  url(r'^', include('django_sshkey.urls')),
  url(r'^admin/doc/', include('django.contrib.admindocs.urls')),
  url(r'^admin/', include(admin.site.urls)),
)
