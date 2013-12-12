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

def lookup_command(args):
  import sys
  import urllib
  if len(args) == 1:
    url = args[0]
    line = sys.stdin.readline()
    if not line:
      sys.stderr.write('no input given\n')
      sys.exit(2)
    fingerprint = sshkey_fingerprint(line)
    url += '?fingerprint=' + urllib.quote_plus(fingerprint)
  elif len(args) == 2:
    url, username = args
    url += '?username=' + urllib.quote_plus(username)
  else:
    sys.stderr.write('Invalid number of arguments\n')
    sys.exit(2)
  response = urllib.urlopen(url)
  status = 1
  for line in response.readlines():
    status = 0
    sys.stdout.write(line)
  sys.exit(status)

def lookup_main():
  import sys
  lookup_command(sys.argv[1:])
