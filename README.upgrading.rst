Upgrading and Downgrading
=========================

django-sshkey is equipped with South_ migrations.  This makes changes to the
database schema in upgrades or downgrades a simple process.  Migrations will
only be present on minor version changes.

To use South migrations, you must have the south app in your project's
``INSTALLED_APPS``.

The following table maps django-sshkey version to migration labels:

+---------+---------------+-------+------------------------------------------+
| Version | App Name      | Label | Notes                                    |
+=========+===============+=======+==========================================+
| 1.0     | sshkey        | 0001  | Migrations were not present in 1.0.x     |
+---------+---------------+-------+------------------------------------------+
| 1.1     | sshkey        | 0002  |                                          |
+---------+---------------+-------+------------------------------------------+
| 2.0+    | django_sshkey | 0001  | See Upgrading from 1.1.x to 2.x below    |
+---------+---------------+-------+------------------------------------------+

To upgrade, install the new version of django-sshkey and then migrate your
project to its corresponding label from the table above using the following
command::

  python manage.py migrate APP_NAME LABEL

To downgrade, perform the migration down to the label of the desired version
before installing the older django-sshkey.

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
