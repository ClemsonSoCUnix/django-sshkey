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
