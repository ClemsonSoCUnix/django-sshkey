django-sshkey lets you use a patched OpenSSH server to authenticate incoming
SSH connections via public key authentication and identify the Django User that
owns that key.

# The OpenSSH Patch

At the top level of this repository is a patch for OpenSSH 6.2p2 which modifies
the AuthorizedKeysCommand config option so that the incoming SSH public key is
passed to the command via standard input.  The incoming username will still be
passed as the first argument to the specified command.

# The Django app

The Django app is located in the sshkey directory at the top level of this
repository.  You should point Django to it in your project's settings.py or
copy it into your project's directory.

In order to associate an incoming public key with a user you must define
SSHKEY\_AUTHORIZED\_KEYS\_COMMAND in your project's settings.py.  This should
be a string containing the command which is run after successful
authentication, with "{username}" being replaced with the username of the user
associated with the incoming public key.  For instance:

> SSHKEY\_AUTHORIZED\_KEYS\_COMMAND = 'my-command {username}'

will cause keys produced by the below commands to look similar to:

> command="my-command fred" ssh-rsa BLAHBLAHBLAH

assuming the key "BLAHBLAHBLAH" is owned by fred.

## URL Configuration

This text assumes that your Django project's urls.py maps sshkey.urls into the
url namespace as follows:

> urlpatterns = patterns('',
>   ...
>   url('^sshkey/', include(sshkey.urls)),
>   ...
> )

You will need to adjust your URLs if you use a different mapping.

# Tying OpenSSH's AuthorizedKeysCommand to the sshkey Django app

There are three provided ways of connecting AuthorizedKeysCommand to Django.
In all cases it is recommended and/or required that the command specified with
AuthorizedKeysCommand be a shell script that is owned by and only writable by
root which invokes one of the commands below:

## Using lookup.sh

*Usage: lookup.sh URL [USERNAME]*

URL should be the full URL to /sshkey/lookup on your Django web server running
the sshkey app.

If USERNAME is specified, lookup keys owned by that user and print them to
standard output. Any standard input is ignored.

If USERNAME is not specified, the incoming public key should be provided on
standard input; if the key is found it is printed to standard output.

This command assumes that some fairly standard commands, like ssh-keygen and
curl, are found in $PATH.

This is generally the fastest method.

## Using lookup.py

*Usage: lookup.py URL [USERNAME]*

Same as above, but it's all written in Python and doesn't rely on external
commands.

The parent directory of the sshkey app must be in PYTHONPATH.

This is generally the second fastest method.

## Using manage.py sshkey\_authorized\_keys\_command

*Usage: PATH\_TO\_DJANGO\_PROJECT/manage.py sshkey\_authorized\_keys\_command [USERNAME]*

Same semantics for USERNAME as above.

This method does not rely on the /sshkey/lookup URL, and instead creates its
own database connection each time it is invoked.

This is generally the slowest method.
