from django.conf import settings

SSHKEY_AUTHORIZED_KEYS_OPTIONS = getattr(settings, 'SSHKEY_AUTHORIZED_KEYS_OPTIONS', None)
SSHKEY_AUTHORIZED_KEYS_COMMAND = getattr(settings, 'SSHKEY_AUTHORIZED_KEYS_COMMAND', None)
if SSHKEY_AUTHORIZED_KEYS_COMMAND is not None:
  import warnings
  with warnings.catch_warnings():
    import warnings
    warnings.simplefilter('default', DeprecationWarning)
    warnings.warn(
      'SSHKEY_AUTHORIZED_KEYS_COMMAND has been deprecated; '
      'use SSHKEY_AUTHORIZED_KEYS_OPTIONS instead.',
      DeprecationWarning)
