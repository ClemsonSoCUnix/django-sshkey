===============================
Release Notes for django-sshkey
===============================

2.3.1 (2014-07-29)
------------------

* Add support for Django 1.6
* Add missing dependency for pyasn1 (introduced in 2.3.0)
* Add release notes (this file)

2.3.0 (2014-07-07)
------------------

* Schema change (label 0002): add last_used timestamp
* Provide {key_id} in template for SSHKEY_AUTHORIZED_KEYS_OPTIONS so that
  last_used timestamp may be updated
* Add support for RFC4716 and PEM public keys for import and export
* django-sshkey-lookup can now use any method to lookup keys: all, by username,
  by fingerprint, or compatibility mode
* Add ability to send email to user when a key is added to their account
* Add the following settings
    * SSHKEY_ALLOW_EDIT
    * SSHKEY_EMAIL_ADD_KEY
    * SSHKEY_EMAIL_ADD_KEY_SUBJECT
    * SSHKEY_FROM_EMAIL
    * SSHKEY_SEND_HTML_EMAIL
* Remove setting SSHKEY_AUTHORIZED_KEYS_COMMAND (deprecated since 1.0.0)
* Fix up example templates

2.2.0 (2014-03-26)
------------------

* Change license to BSD 3-clause
* Basic compatability with Django > 1.3
* OpenSSH patch removed, refer to their separate projects
* Remove deprecated sshkey_authorized_keys_command management command
* Add the following lookup commands
    * django-sshkey-lookup-all
    * django-sshkey-lookup-by-fingerprint
    * django-sshkey-lookup-by-username

2.1.0 (2014-01-22)
------------------

* lookup.sh and lookup.py deprecated in favor of django-sshkey-lookup and
  django-sshkey-pylookup, respectively
* Install scripts using setuptools

2.0.1 (2013-09-30)
------------------

* Add missing __init__.py

2.0.0 (2013-09-30)
------------------

* Rename sshkey to django_sshkey

1.1.1 (2013-09-03)
------------------

* Include management and migrations directories in setuptools

1.1.0 (2013-08-28)
------------------

* Schema change (label 0001): add created and last_modified timestamps

1.0.1 (2013-08-28)
------------------

* Add copyright info

1.0.0 (2013-08-28)
------------------

First release
