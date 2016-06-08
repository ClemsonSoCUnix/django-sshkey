# Copyright (c) 2014-2016, Clemson University
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
# * Neither the name of Clemson University nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import base64
import binascii
import struct

SSHKEY_LOOKUP_URL_DEFAULT = 'http://localhost:8000/sshkey/lookup'


def wrap(text, width, wrap_end=None):
  n = 0
  t = ''
  if wrap_end is None:
    while n < len(text):
      m = n + width
      t += text[n:m]
      if len(text) <= m:
        return t
      t += '\n'
      n = m
  else:
    while n < len(text):
      m = n + width
      if len(text) <= m:
        return t + text[n:m]
      m -= len(wrap_end)
      t += text[n:m] + wrap_end + '\n'
      n = m
  return t


def bytes2int(b):
  h = binascii.hexlify(b)
  return int(h, 16)


def int2bytes(i):
  h = '%x' % i
  if len(h) & 1:
    h = '0' + h
  return bytearray.fromhex(h)


class PublicKeyParseError(Exception):
  def __init__(self, text):
    self.text = text

  def __str__(self):
    return "Unrecognized public key format"


class PublicKey(object):
  def __init__(self, b64key, comment=None):
    self.b64key = b64key
    self.comment = comment
    try:
      keydata = base64.b64decode(b64key.encode('ascii'))
    except binascii.Error as e:  # Python 3 raises this instead of TypeError
      raise TypeError(str(e))
    self.keydata = keydata
    self.parts = []
    while keydata:
      dlen = struct.unpack('>I', keydata[:4])[0]
      data, keydata = keydata[4:4 + dlen], keydata[4 + dlen:]
      self.parts.append(data)
    self.algorithm = self.parts[0].decode('ascii')

  def fingerprint(self):
    import hashlib
    fp = hashlib.md5(self.keydata).hexdigest()
    return ':'.join(a + b for a, b in zip(fp[::2], fp[1::2]))

  def format_openssh(self):
    out = self.algorithm + ' ' + self.b64key
    if self.comment:
      out += ' ' + self.comment
    return out

  def format_rfc4716(self):
    out = '---- BEGIN SSH2 PUBLIC KEY ----\n'
    if self.comment:
      comment = 'Comment: "%s"' % self.comment
      out += wrap(comment, 72, '\\') + '\n'
    out += wrap(self.b64key, 72) + '\n'
    out += '---- END SSH2 PUBLIC KEY ----'
    return out

  def format_pem(self):
    if self.algorithm != 'ssh-rsa' and len(self.parts) == 3:
      raise TypeError("key is not a valid RSA key")
    from pyasn1.codec.der import encoder as der_encoder
    from pyasn1.type import univ
    e = bytes2int(self.parts[1])
    n = bytes2int(self.parts[2])
    pkcs1_seq = univ.Sequence()
    pkcs1_seq.setComponentByPosition(0, univ.Integer(n))
    pkcs1_seq.setComponentByPosition(1, univ.Integer(e))
    der = der_encoder.encode(pkcs1_seq)
    out = (
      '-----BEGIN RSA PUBLIC KEY-----\n' +
      wrap(base64.b64encode(der).decode('ascii'), 64) + '\n' +
      '-----END RSA PUBLIC KEY-----'
    )
    return out


def pubkey_parse_openssh(text):
  fields = text.split(None, 2)
  if len(fields) < 2:
    raise PublicKeyParseError(text)
  try:
    if len(fields) == 2:
      key = PublicKey(fields[1])
    else:
      key = PublicKey(fields[1], fields[2])
  except TypeError:
    raise PublicKeyParseError(text)
  if fields[0] != key.algorithm:
    raise PublicKeyParseError(text)
  return key


def pubkey_parse_rfc4716(text):
  lines = text.splitlines()
  if not (
    lines[0] == '---- BEGIN SSH2 PUBLIC KEY ----' and
    lines[-1] == '---- END SSH2 PUBLIC KEY ----'
  ):
    raise PublicKeyParseError(text)
  lines = lines[1:-1]
  b64key = ''
  headers = {}
  while lines:
    line = lines.pop(0)
    if ':' in line:
      while line[-1] == '\\':
        line = line[:-1] + lines.pop(0)
      k, v = line.split(':', 1)
      headers[k.lower()] = v.lstrip()
    else:
      b64key += line
  comment = headers.get('comment')
  if comment and comment[0] in ('"', "'") and comment[0] == comment[-1]:
    comment = comment[1:-1]
  try:
    return PublicKey(b64key, comment)
  except TypeError:
    raise PublicKeyParseError(text)


def pubkey_parse_pem(text):
  from pyasn1.codec.der import decoder as der_decoder
  lines = text.splitlines()
  if not (
    lines[0] == '-----BEGIN RSA PUBLIC KEY-----' and
    lines[-1] == '-----END RSA PUBLIC KEY-----'
  ):
    raise PublicKeyParseError(text)
  der = base64.b64decode(''.join(lines[1:-1]).encode('ascii'))
  pkcs1_seq = der_decoder.decode(der)
  n_val = pkcs1_seq[0][0]
  e_val = pkcs1_seq[0][1]
  n = int2bytes(n_val)
  e = int2bytes(e_val)
  if n[0] & 0x80:
      n = b'\x00' + n
  if e[0] & 0x80:
      e = b'\x00' + e
  algorithm = 'ssh-rsa'.encode('ascii')
  keydata = (
    struct.pack('>I', len(algorithm)) +
    algorithm +
    struct.pack('>I', len(e)) +
    e +
    struct.pack('>I', len(n)) +
    n
  )
  b64key = base64.b64encode(keydata).decode('ascii')
  return PublicKey(b64key)


def pubkey_parse(text):
  lines = text.splitlines()

  if len(lines) == 1:
    return pubkey_parse_openssh(text)

  if lines[0] == '---- BEGIN SSH2 PUBLIC KEY ----':
    return pubkey_parse_rfc4716(text)

  if lines[0] == '-----BEGIN RSA PUBLIC KEY-----':
    return pubkey_parse_pem(text)

  raise PublicKeyParseError(text)


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
        pubkey = pubkey_parse(key)
      except PublicKeyParseError as e:
        sys.stderr.write("Error: " + str(e))
        sys.exit(1)
      fingerprint = pubkey.fingerprint()
  url = getenv('SSHKEY_LOOKUP_URL', SSHKEY_LOOKUP_URL_DEFAULT)
  for key in lookup_by_fingerprint(url, fingerprint):
    sys.stdout.write(key)


def lookup_main():
  import sys
  import getopt
  from os import environ
  usage = (
    "Usage: {prog} -a URL\n"
    "       {prog} -u URL USERNAME\n"
    "       {prog} -f URL FINGERPRINT\n"
    "       {prog} URL [USERNAME]\n"
  ).format(prog=sys.argv[0])
  try:
    opts, args = getopt.getopt(sys.argv[1:], 'hafu')
  except getopt.GetoptError as e:
    sys.stderr.write("Error: %s\n" % str(e))
    sys.stderr.write(usage)
    sys.exit(1)
  mode = 'x'
  for o, a in opts:
    if o == '-h':
      sys.stdout.write(usage)
      sys.exit(0)
    else:
      mode = o[1]
  if len(args) == 0:
    sys.stderr.write(usage)
    sys.exit(1)
  url = args[0]

  if mode == 'a':
    response = lookup_all(url)
  elif mode == 'f':
    if len(args) < 2:
      sys.stderr.write(usage)
      sys.exit(1)
    response = lookup_by_fingerprint(url, args[1])
  elif mode == 'u':
    if len(args) < 2:
      sys.stderr.write(usage)
      sys.exit(1)
    response = lookup_by_username(url, args[1])
  else:
    if len(args) == 1:
      environ['SSHKEY_LOOKUP_URL'] = url
      return lookup_by_fingerprint_main()
    else:
      response = lookup_by_username(url, args[1])

  for key in response:
    sys.stdout.write(key)
