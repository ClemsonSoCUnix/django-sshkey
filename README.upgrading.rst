Upgrading and Downgrading
=========================

From django-sshkey 1.1 to 2.3, South_ migrations were provided. Starting with
2.4, South support was discontinued in favor of the Django native migration
system.

The following table maps django-sshkey version to migration labels:

+---------+---------------+-------+------------------------------------------+
| Version | App Name      | Label | Notes                                    |
+=========+===============+=======+==========================================+
| 1.0     | sshkey        | 0001  | Migrations were not present in 1.0.x     |
+---------+---------------+-------+------------------------------------------+
| 1.1     | sshkey        | 0002  |                                          |
+---------+---------------+-------+------------------------------------------+
| 2.0-2.2 | django_sshkey | 0001  | See Upgrading from 1.1.x to 2.x below    |
+---------+---------------+-------+------------------------------------------+
| 2.3     | django_sshkey | 0002  |                                          |
+---------+---------------+-------+------------------------------------------+
| 2.4     | django_sshkey | 0001  | Django native migrations started.        |
+---------+---------------+-------+------------------------------------------+

To upgrade, install the new version of django-sshkey and then migrate your
project to its corresponding label from the table above using the following
command::

  python manage.py migrate APP_NAME LABEL

To downgrade, perform the migration down to the label of the desired version
before installing the older django-sshkey.

Upgrading from <=2.3.x to 2.4.x
-------------------------------

Starting with django-sshkey 2.4, South support is discontinued in favor of
Django's native migration system. The preferred upgrade path for pre-2.4
installations of django-sshkey is:

1. Upgrade to South 1.0+.
2. Upgrade to django-sshkey 2.3 using the South migrations.
3. Remove south from your ``INSTALLED_APPS``.
4. Upgrade to Django 1.7+ and django-sshkey 2.4+.
5. Run ``python manage.py migrate --fake-initial``.

You may also read Django's instructions on `upgrading from south`_.

.. _`upgrading from south`: https://docs.djangoproject.com/en/dev/topics/migrations/#upgrading-from-south

Upgrading from 1.1.x to 2.x
---------------------------

django-sshkey 2.x renames the sshkey app to django_sshkey.  However, the
database table names are not changed.

To upgrade, all references to the sshkey module must be changed to
django_sshkey.  This includes all instances of ``import sshkey`` or
``from sshkey import ...`` and all references to sshkey in URL patterns,
views, or templates, as well as updating ``INSTALLED_APPS`` in ``settings.py``.

Once you have made those changes you will need to fake the initial migration
for django_sshkey::

  python manage.py migrate --fake django_sshkey 0001_initial

This completes the upgrade process.  The only thing that remains is the two
existing migration records in the ``south_migrationhistory`` table from the
now nonexistent sshkey app.  These records do not cause any problems, but they
can be removed at your discrection using the following SQL statement on your
database::

  DELETE FROM south_migrationhistory WHERE app_name="sshkey";

.. _South: http://south.aeracode.org/
