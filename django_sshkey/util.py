# Copyright (c) 2014, Clemson University
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the {organization} nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from collections import namedtuple

SSHKEY_LOOKUP_URL_DEFAULT = 'http://localhost:8000/sshkey/lookup'

KeyInfo = namedtuple('KeyInfo', 'type b64key comment fingerprint')

class SSHKeyFormatError(Exception):
  def __init__(self, text):
    self.text = text

  def __str__(self):
    return "Unrecognized public key format"

def key_parse(text):
  import base64
  import hashlib
  import struct
  lines = text.splitlines()

  # OpenSSH public key
  if len(lines) == 1 and text.startswith(b'ssh-'):
    fields = text.split(None, 2)
    if len(fields) < 2:
      raise SSHKeyFormatError(text)
    type = fields[0]
    b64key = fields[1]
    comment = None
    if len(fields) == 3:
      comment = fields[2]
    try:
      key = base64.b64decode(b64key)
    except TypeError:
      raise SSHKeyFormatError(text)

  # SSH2 public key
  elif (
    lines[0] == b'---- BEGIN SSH2 PUBLIC KEY ----'
    and lines[-1] == b'---- END SSH2 PUBLIC KEY ----'
  ):
    b64key = b''
    headers = {}
    lines = lines[1:-1]
    while lines:
      line = lines.pop(0)
      if b':' in line:
        while line[-1] == b'\\':
          line = line[:-1] + lines.pop(0)
        k,v = line.split(b':', 1)
        headers[k.lower().decode('ascii')] = v.lstrip().decode('utf-8')
      else:
        b64key += line
    comment = headers.get('comment')
    if comment and comment[0] in ('"', "'") and comment[0] == comment[-1]:
      comment = comment[1:-1]
    try:
      key = base64.b64decode(b64key)
    except TypeError:
      raise SSHKeyFormatError(text)
    if len(key) < 4:
      raise SSHKeyFormatError(text)
    n = struct.unpack('>I', key[:4])
    type = key[4:4+n[0]]

  # unrecognized format
  else:
    raise SSHKeyFormatError(text)

  fp = hashlib.md5(key).hexdigest()
  fp = ':'.join(a+b for a,b in zip(fp[::2], fp[1::2]))
  return KeyInfo(type, b64key, comment, fp)

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
      try:
        type, b64key, comment, fingerprint = key_parse(key)
      except SSHKeyFormatError as e:
        sys.stderr.write("Error: " + str(e))
        sys.exit(1)
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
