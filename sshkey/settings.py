# Copyright 2013 Scott Duckworth
#
# This file is part of django-sshkey.
#
# django-sshkey is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# django-sshkey is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with django-sshkey.  If not, see <http://www.gnu.org/licenses/>.

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
