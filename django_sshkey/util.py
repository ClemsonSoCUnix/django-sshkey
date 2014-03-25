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

import re

SSHKEY_LOOKUP_URL_DEFAULT = 'http://localhost:8000/sshkey/lookup'

sshkey_re = re.compile(r'(?P<type>[\w-]+)\s+(?P<b64key>\S+)(?:\s+(?P<comment>\S.+))?$')

def sshkey_fingerprint(b64key):
  import base64
  import hashlib
  key = base64.b64decode(b64key)
  fp_plain = hashlib.md5(key).hexdigest()
  return ':'.join(a+b for a,b in zip(fp_plain[::2], fp_plain[1::2]))

def lookup_all(url):
  import urllib
  response = urllib.urlopen(url)
  return response.readlines()

def lookup_by_username(url, username):
  import urllib
  url += '?' + urllib.urlencode({'username': username})
  response = urllib.urlopen(url)
  return response.readlines()

def lookup_by_fingerprint(url, fingerprint):
  import urllib
  url += '?' + urllib.urlencode({'fingerprint': fingerprint})
  response = urllib.urlopen(url)
  return response.readlines()

def lookup_all_main():
  import sys
  from os import getenv
  url = getenv('SSHKEY_LOOKUP_URL', SSHKEY_LOOKUP_URL_DEFAULT)
  for key in lookup_all(url):
    sys.stdout.write(key)

def lookup_by_username_main():
  import sys
  from os import getenv
  if len(sys.argv) < 2:
    sys.stderr.write('Usage: %s USERNAME\n' % sys.argv[0])
    sys.exit(1)
  username = sys.argv[1]
  url = getenv('SSHKEY_LOOKUP_URL', SSHKEY_LOOKUP_URL_DEFAULT)
  for key in lookup_by_username(url, username):
    sys.stdout.write(key)

def lookup_by_fingerprint_main():
  import sys
  from os import getenv
  fingerprint = getenv('SSH_KEY_FINGERPRINT')
  if fingerprint is None:
    key = getenv('SSH_KEY')
    if key is None:
      key = sys.stdin.readline()
      if not key:
        sys.stderr.write(
          "Error: cannot retrieve fingerprint from environment or stdin\n"
        )
        sys.exit(1)
      m = sshkey_re.match(key)
      if not m:
        sys.stderr.write(
          "Error: cannot parse SSH protocol 2 base64-encoded key"
        )
        sys.exit(1)
      fingerprint = sshkey_fingerprint(m.group('b64key'))
  url = getenv('SSHKEY_LOOKUP_URL', SSHKEY_LOOKUP_URL_DEFAULT)
  for key in lookup_by_fingerprint(url, fingerprint):
    sys.stdout.write(key)

def lookup_main():
  import sys
  from os import environ
  if len(sys.argv) < 2:
    sys.stderr.write('Usage: %s URL [USERNAME]\n' % sys.argv[0])
    sys.exit(1)
  url = sys.argv[1]
  if len(sys.argv) == 2:
    environ['SSHKEY_LOOKUP_URL'] = url
    lookup_by_fingerprint_main()
  else:
    username = sys.argv[2]
    for key in lookup_by_username(url, username):
      sys.stdout.write(key)
