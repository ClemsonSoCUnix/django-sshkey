=============
django-sshkey
=============

django-sshkey allows you to associate multiple SSH public keys with Django
user accounts.  It provides views to list, add, edit, and delete keys, each of
which is intended for end-user consumption.  It also provides a lookup view
and corresponding lookup commands that are suitable for use with the
``AuthorizedKeysCommand`` feature in OpenSSH_ 6.2 and above.

The Django app
==============

To use django-sshkey in your Django project, simply add ``django_sshkey`` to
``INSTALLED_APPS`` in ``settings.py``, map the URLs into your project, and
provide templates for the views (example templates are provided in the source).

In order to associate an incoming public key with a user you must define
``SSHKEY_AUTHORIZED_KEYS_OPTIONS`` in your project's ``settings.py``.  This
should be a string containing options accepted by sshd, with ``{username}``
being replaced with the username of the user associated with the incoming
public key.

django-sshkey can also help you keep track of when a key was last used.
``SSHKEY_AUTHORIZED_KEYS_OPTIONS`` also replaces ``{key_id}`` with the key's
id.  The command that is run can then notify django-sshkey that the key was used
by issuing a HTTP POST to the lookup URL, placing the key_id in the request
body.

For instance::

  SSHKEY_AUTHORIZED_KEYS_OPTIONS = 'command="my-command {username} {key_id}",no-pty'

in settings.py will cause keys produced by the below commands to look similar
to::

  command="my-command fred 15",no-pty ssh-rsa AAAAB3NzaC1yc2E...

sshd would then verify the key is correct and run ``my-command``.
``my-command`` would then know that this is fred and that he is using key 15,
and could tell django-sshkey to update the last_used field of that key by
running the equivalent of this command::

  curl -d 15 http://localhost:8000/sshkey/lookup

Your URL may vary depending upon your configuration.

URL Configuration
-----------------

This text assumes that your project's ``urls.py`` maps ``django_sshkey.urls``
into the URL namespace as follows::

  import django_sshkey.urls
  urlpatterns = patterns('',
    ...
    url('^sshkey/', include(django_sshkey.urls)),
    ...
  )

You will need to adjust your URLs in the examples below if you use a different
mapping.

.. WARNING::

  The ``/sshkey/lookup`` URL can expose all public keys that have
  been uploaded to your site.  Although they are public keys, it is probably a
  good idea to limit what systems can access this URL via your web server's
  configuration.  Most of the lookup methods below require access to this URL,
  and only the systems that need to run the lookup commands should have access
  to it.

Settings
--------

``SSHKEY_AUTHORIZED_KEYS_OPTIONS``
  String, optional.  Defines the SSH options that will be prepended to each
  public key.  ``{username}`` will be replaced by the username; ``{key_id}``
  will be replaced by the key's id.  New in version 2.3.

``SSHKEY_ALLOW_EDIT``
  Boolean, defaults to ``False``.  Whether or not editing keys is allowed.
  Note that no email will be sent in any case when a key is edited, hence the
  reason that editing keys is disabled by default.  New in version 2.3.

``SSHKEY_DEFAULT_HASH``
  String, either ``sha256``, ``md5``, or ``legacy`` (the default).  The default
  hash algorithm to use for calculating the finger print of keys.  Legacy
  behavior enforces OpenSSH's pre-6.8 behavior of MD5 without the ``MD5:``
  prefix.  New in version 2.5.

``SSHKEY_EMAIL_ADD_KEY``
  Boolean, defaults to ``True``.  Whether or not an email should be sent to the
  user when a new key is added to their account.  New in version 2.3.

``SSHKEY_EMAIL_ADD_KEY_SUBJECT``
  String, defaults to ``"A new key was added to your account"``.  The subject of
  the email that gets sent out when a new key is added.  New in version 2.3.

``SSHKEY_FROM_EMAIL``
  String, defaults to ``DEFAULT_FROM_EMAIL``.  New in version 2.3.

``SSHKEY_SEND_HTML_EMAIL``
  Boolean, defaults to ``False``.  Whether or not multipart HTML emails should
  be sent.  New in version 2.3.

Templates
---------

Example templates are available in the ``templates.example`` directory.

``sshkey/userkey_list.html``
  Used when listing a user's keys.

``sshkey/userkey_detail.html``
  Used when adding or editing a user's keys.

``sshkey/add_key.txt``
  The plain text body of the email sent when a new key is added.  New in version
  2.3.

``sshkey/add_key.html``
  The HTML body of the email sent when a new key is added.  New in version 2.3.

Tying OpenSSH to django-sshkey
==============================

There are multiple methods of connecting OpenSSH to django-sshkey.  All of the
methods listed here require the use of the ``AuthorizedKeysCommand`` directive
in ``sshd_config`` present in OpenSSH 6.2 and above.  Please note that the
command that is referenced by this directive and its ancestor directories must
be owned by root and writable only by owner.

Unless otherwise stated, all of the methods below use the ``SSHKEY_LOOKUP_URL``
environment variable to determine the URL of the ``/sshkey/lookup`` URL.  If
this environment variable is not defined then it will default to
``http://localhost:8000/sshkey/lookup``.  If this environment variable is
defined in the sshd process then it will be inherited by the
``AuthorizedKeysCommand``.

Additionally, all of the methods below use either ``curl`` (preferred) or
``wget``.  Some commands also use ``ssh-keygen``.  These commands must be
present in ``PATH``.

If you would prefer not to use these external commands then there are variants
of the lookup commands implemented purely in Python.  However, they are *much*
slower.  To use the variants, replace ``lookup`` with ``pylookup``.  For
example, use ``django-sshkey-pylookup-all`` instead of
``django-sshkey-lookup-all``.

Using ``django-sshkey-lookup``
------------------------------

::

  Usage: django-sshkey-lookup -a URL
         django-sshkey-lookup -u URL USERNAME
         django-sshkey-lookup -f URL FINGERPRINT
         django-sshkey-lookup URL [USERNAME]

This program has different modes of operation:

``-a``
  Print all public keys.

``-u``
  Print all public keys owned by the specified user.

``-f``
  Print all public keys matching the specified fingerprint.

Default
  Compatibility mode.  If the username parameter is given then print all public
  keys owned by the specified user; otherwise perform the same functionality as
  ``django-sshkey-lookup-by-fingerprint`` (see below).

All modes expect that the lookup URL be specified as the first non-option
parameter.

This command is compatible with the old script ``lookup.sh`` but was renamed
to have a less ambiguous name when installed system-wide. A symlink is left in
its place for backwards compatibility.

Using ``django-sshkey-lookup-all``
----------------------------------

``Usage: django-sshkey-lookup-all``

This program prints all SSH public keys that are defined on your site.  sshd
will have to scan through all of them to find the first match, so with many
keys this method will be slow.  However, it does not require a patched OpenSSH
server.

This program:

* can be used directly with ``AuthorizedKeysCommand`` (the username parameter
  is ignored).

* does not require a patched OpenSSH server.

* does not scale well to a large number of user keys.

Using ``django-sshkey-lookup-by-username``
------------------------------------------

``Usage: django-sshkey-lookup-by-username USERNAME``

This program prints all SSH public keys that are associated with the specified
user.

This program:

* can be used directly with ``AuthorizedKeysCommand``.

* does not require a patched OpenSSH server.

* is ideal if each Django user corresponds to a system user account.

Using ``django-sshkey-lookup-by-fingerprint``
---------------------------------------------

``Usage: django-sshkey-lookup-by-fingerprint``

This program prints all SSH public keys that match the given fingerprint.  The
fingerprint is determined by the first of the following that is found:

1. The ``SSH_KEY_FINGERPRINT`` environment variable, which should contain the
   MD5 fingerprint of the key (this is the second field generated by
   ``ssh-keygen -l``).

2. The ``SSH_KEY`` environment variable, which should contain the key in
   standard openssh format (the same format as ``~/.ssh/id_rsa.pub``), is sent
   to ``ssh-keygen -l`` to determine the fingerprint.

3. The key in standard openssh format is read from standard input and is sent
   to ``ssh-keygen -l`` to determine the fingerprint.

This program:

* can be used directly with ``AuthorizedKeysCommand`` (the username parameter
  is ignored).

* requires a patched OpenSSH server; compatible patches can be found at one of
  the following locations:

  - openssh-akcenv_ (this is the preferred patch)
  - openssh-stdinkey_

* is ideal if you want all Django users to access SSH via a shared system user
  account and be identified by their SSH public key.

.. _OpenSSH: http://www.openssh.com/
.. _openssh-akcenv: https://github.com/ScottDuckworth/openssh-akcenv
.. _openssh-stdinkey: https://github.com/ScottDuckworth/openssh-stdinkey
