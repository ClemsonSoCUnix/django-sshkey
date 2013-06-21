from django.conf.urls.defaults import patterns, url

urlpatterns = patterns('sshkey.views',
  url(r'^lookup$', 'lookup'),
  url(r'^$', 'userkey_list'),
  url(r'^add$', 'userkey_add'),
  url(r'^(?P<pk>\d+)$', 'userkey_edit'),
  url(r'^(?P<pk>\d+)/delete$', 'userkey_delete'),
)
