import base64
import hashlib
import re

sshkey_re = re.compile(r'\s*(?:(?P<options>.*?)\s+)?(?P<type>ssh-\w+)\s+(?P<key>\S+)(?:\s+(?P<comment>\S+))?\s*$')

def sshkey_fingerprint(key_line):
  match = sshkey_re.match(key_line)
  if not match:
    raise Exception('Key is not in OpenSSH authorized_keys format')
  key = base64.b64decode(match.group('key'))
  fp_plain = hashlib.md5(key).hexdigest()
  return ':'.join(a+b for a,b in zip(fp_plain[::2], fp_plain[1::2]))

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
