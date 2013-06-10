from django.conf.urls.defaults import patterns, url

urlpatterns = patterns('sshkey.views',
  url(r'^lookup$', 'lookup'),
)
