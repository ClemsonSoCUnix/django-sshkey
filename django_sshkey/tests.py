# Copyright (c) 2014-2015, Clemson University
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
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from django.test import TestCase
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.core.urlresolvers import reverse
from django_sshkey.models import UserKey
from django_sshkey import settings, util
import os
import shutil
import subprocess
import tempfile
from unittest import skipIf


def ssh_version_name(ssh='ssh'):
  cmd = [ssh, '-V']
  try:
    out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
  except subprocess.CalledProcessError:
    raise RuntimeError('OpenSSH is required to run the testing suite.')
  out = out.decode('ascii')
  out = out.split()[0]
  return out.split('_')[1].rstrip(',')


def parse_ssh_version(version):
  major, minor = version.split('.', 1)
  minor, patch = minor.split('p', 1)
  return (major, minor, patch)


def ssh_keygen(type=None, passphrase='', comment=None, file=None):
  cmd = ['ssh-keygen', '-q']
  if type is not None:
    cmd += ['-t', type]
  if passphrase is not None:
    cmd += ['-N', passphrase]
  if comment is not None:
    cmd += ['-C', comment]
  if file is not None:
    cmd += ['-f', file]
  subprocess.check_call(cmd)


def ssh_key_export(input_path, output_path, format='RFC4716'):
  cmd = ['ssh-keygen', '-e', '-m', format, '-f', input_path]
  with open(output_path, 'wb') as f:
    subprocess.check_call(cmd, stdout=f)


def ssh_key_import(input_path, output_path, format='RFC4716'):
  cmd = ['ssh-keygen', '-i', '-m', format, '-f', input_path]
  with open(output_path, 'wb') as f:
    subprocess.check_call(cmd, stdout=f)


def ssh_fingerprint(pubkey_path, hash=None):
  cmd = ['ssh-keygen', '-lf', pubkey_path]

  # Legacy mode ensures the fingeprint is always a non-prefixed MD5 hash of the
  # key, regardless of which version of OpenSSH is installed.
  legacy = hash == 'legacy'
  if legacy and SSH_VERSION < ('6', '8'):
    hash = None
  elif legacy:
    hash = 'md5'
  if hash is not None:
    cmd.extend(['-E', hash])

  p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
  stdout, stderr = p.communicate()
  if p.returncode != 0:
    raise subprocess.CalledProcessError(p.returncode, cmd)
  fingerprint = stdout.split(None, 2)[1]
  fingerprint = fingerprint.decode('ascii')

  # Strip off the prefix in legacy mode if found.
  if legacy and fingerprint.startswith('MD5:'):
    fingerprint = fingerprint[len('MD5:'):]

  return fingerprint


def read_pubkey(path):
  '''Read an OpenSSH formatted public key'''
  return open(path).read().strip()


SSH_VERSION_NAME = ssh_version_name()
SSH_VERSION = parse_ssh_version(SSH_VERSION_NAME)


class BaseTestCase(TestCase):
  @classmethod
  def setUpClass(cls):
    cls.key_dir = tempfile.mkdtemp(prefix='sshkey-test.')

  @classmethod
  def tearDownClass(cls):
    if cls.key_dir:
      shutil.rmtree(cls.key_dir)
      cls.key_dir = None


class UserKeyCreationTestCase(BaseTestCase):
  @classmethod
  def setUpClass(cls):
    super(UserKeyCreationTestCase, cls).setUpClass()
    cls.user1 = User.objects.create(username='user1')
    cls.user2 = User.objects.create(username='user2')
    # key1 has a comment
    cls.key1_path = os.path.join(cls.key_dir, 'key1')
    ssh_keygen(comment='comment', file=cls.key1_path)
    # key2 does not have a comment
    cls.key2_path = os.path.join(cls.key_dir, 'key2')
    ssh_keygen(comment='', file=cls.key2_path)

  @classmethod
  def tearDownClass(cls):
    User.objects.all().delete()
    super(UserKeyCreationTestCase, cls).tearDownClass()

  def setUp(self):
    self._default_hash = settings.SSHKEY_DEFAULT_HASH

  def tearDown(self):
    settings.SSHKEY_DEFAULT_HASH = self._default_hash
    UserKey.objects.all().delete()

  def test_with_name_with_comment(self):
    key = UserKey(
      user=self.user1,
      name='name',
      key=open(self.key1_path + '.pub').read(),
    )
    key.full_clean()
    key.save()
    self.assertEqual(key.name, 'name')

  def test_with_name_without_comment(self):
    key = UserKey(
      user=self.user1,
      name='name',
      key=open(self.key2_path + '.pub').read(),
    )
    key.full_clean()
    key.save()
    self.assertEqual(key.name, 'name')

  def test_without_name_with_comment(self):
    key = UserKey(
      user=self.user1,
      key=open(self.key1_path + '.pub').read(),
    )
    key.full_clean()
    key.save()
    self.assertEqual(key.name, 'comment')

  def test_without_name_without_comment_fails(self):
    key = UserKey(
      user=self.user1,
      key=open(self.key2_path + '.pub').read(),
    )
    self.assertRaises(ValidationError, key.full_clean)

  def test_private_key_fails(self):
    key = UserKey(
      user=self.user1,
      name='name',
      key=open(self.key1_path).read(),
    )
    self.assertRaises(ValidationError, key.full_clean)

  def test_invalid_key_fails(self):
    key = UserKey(
      user=self.user1,
      name='name',
      key='ssh-rsa invalid',
    )
    self.assertRaises(ValidationError, key.full_clean)

  def test_key_with_options_fails(self):
    key = UserKey(
      user=self.user1,
      name='name',
      key='command="foobar" ' + open(self.key1_path + '.pub').read(),
    )
    self.assertRaises(ValidationError, key.full_clean)

  def test_multiple_keys_fails(self):
    key = UserKey(
      user=self.user1,
      name='name',
      key=(open(self.key1_path + '.pub').read() +
           open(self.key2_path + '.pub').read()),
    )
    self.assertRaises(ValidationError, key.full_clean)

  def test_fingerprint_legacy(self):
    settings.SSHKEY_DEFAULT_HASH = 'legacy'
    fingerprint = ssh_fingerprint(self.key1_path + '.pub', hash='legacy')
    key = UserKey(
      user=self.user1,
      name='name',
      key=open(self.key1_path + '.pub').read(),
    )
    key.full_clean()
    key.save()
    self.assertEqual(key.fingerprint, fingerprint)

  def test_fingerprint_sha256(self):
    settings.SSHKEY_DEFAULT_HASH = 'sha256'
    key = UserKey(
      user=self.user1,
      name='name',
      key=open(self.key1_path + '.pub').read(),
    )
    key.full_clean()
    key.save()
    self.assertTrue(key.fingerprint.startswith('SHA256:'))

  def test_fingerprint_md5(self):
    settings.SSHKEY_DEFAULT_HASH = 'md5'
    key = UserKey(
      user=self.user1,
      name='name',
      key=open(self.key1_path + '.pub').read(),
    )
    key.full_clean()
    key.save()
    self.assertTrue(key.fingerprint.startswith('MD5:'))

  def test_touch(self):
    import datetime
    key = UserKey(
      user=self.user1,
      name='name',
      key=open(self.key1_path + '.pub').read(),
    )
    key.full_clean()
    key.save()
    self.assertIsNone(key.last_used)
    key.touch()
    key.save()
    self.assertIsInstance(key.last_used, datetime.datetime)
    key.touch()

  def test_same_name_same_user(self):
    key1 = UserKey(
      user=self.user1,
      name='name',
      key=open(self.key1_path + '.pub').read(),
    )
    key1.full_clean()
    key1.save()
    key2 = UserKey(
      user=self.user1,
      name='name',
      key=open(self.key2_path + '.pub').read(),
    )
    self.assertRaises(ValidationError, key2.full_clean)

  def test_same_name_different_user(self):
    key1 = UserKey(
      user=self.user1,
      name='name',
      key=open(self.key1_path + '.pub').read(),
    )
    key1.full_clean()
    key1.save()
    key2 = UserKey(
      user=self.user2,
      name='name',
      key=open(self.key2_path + '.pub').read(),
    )
    key2.full_clean()
    key2.save()

  def test_same_key_same_user(self):
    key1 = UserKey(
      user=self.user1,
      name='name1',
      key=open(self.key1_path + '.pub').read(),
    )
    key1.full_clean()
    key1.save()
    key2 = UserKey(
      user=self.user1,
      name='name2',
      key=open(self.key1_path + '.pub').read(),
    )
    self.assertRaises(ValidationError, key2.full_clean)

  def test_same_key_different_user(self):
    key1 = UserKey(
      user=self.user1,
      name='name1',
      key=open(self.key1_path + '.pub').read(),
    )
    key1.full_clean()
    key1.save()
    key2 = UserKey(
      user=self.user2,
      name='name2',
      key=open(self.key1_path + '.pub').read(),
    )
    self.assertRaises(ValidationError, key2.full_clean)

  def test_blank_key_fails(self):
    key = UserKey(
      user=self.user1,
      name='name1',
      key='',
    )
    self.assertRaises(ValidationError, key.full_clean)

  def test_ws_key_fails(self):
    key = UserKey(
      user=self.user1,
      name='name1',
      key='     ',
    )
    self.assertRaises(ValidationError, key.full_clean)


class RFC4716TestCase(BaseTestCase):
  @classmethod
  def setUpClass(cls):
    super(RFC4716TestCase, cls).setUpClass()
    cls.user1 = User.objects.create(username='user1')
    # key1 has a comment
    cls.key1_path = os.path.join(cls.key_dir, 'key1')
    cls.key1_rfc4716_path = os.path.join(cls.key_dir, 'key1.rfc4716')
    ssh_keygen(comment='comment', file=cls.key1_path)
    ssh_key_export(cls.key1_path, cls.key1_rfc4716_path, 'RFC4716')
    # key2 does not have a comment
    cls.key2_path = os.path.join(cls.key_dir, 'key2')
    cls.key2_rfc4716_path = os.path.join(cls.key_dir, 'key2.rfc4716')
    ssh_keygen(comment='', file=cls.key2_path)
    ssh_key_export(cls.key2_path, cls.key2_rfc4716_path, 'RFC4716')

  @classmethod
  def tearDownClass(cls):
    User.objects.all().delete()
    super(RFC4716TestCase, cls).tearDownClass()

  def tearDown(self):
    UserKey.objects.all().delete()

  def test_import_with_comment(self):
    key = UserKey(
      user=self.user1,
      name='name',
      key=open(self.key1_rfc4716_path).read(),
    )
    key.full_clean()
    key.save()
    self.assertEqual(key.key.split()[:2],
                     open(self.key1_path + '.pub').read().split()[:2])

  def test_import_without_comment(self):
    key = UserKey(
      user=self.user1,
      name='name',
      key=open(self.key2_rfc4716_path).read(),
    )
    key.full_clean()
    key.save()
    self.assertEqual(key.key.split()[:2],
                     open(self.key2_path + '.pub').read().split()[:2])

  def test_export(self):
    key = UserKey(
      user=self.user1,
      name='name',
      key=open(self.key1_path + '.pub').read(),
    )
    key.full_clean()
    key.save()
    export_path = os.path.join(self.key_dir, 'export')
    import_path = os.path.join(self.key_dir, 'import')
    with open(export_path, 'w') as f:
      f.write(key.export('RFC4716'))
    ssh_key_import(export_path, import_path, 'RFC4716')
    self.assertEqual(open(import_path).read().split()[:2],
                     open(self.key1_path + '.pub').read().split()[:2])


class PemTestCase(BaseTestCase):
  @classmethod
  def setUpClass(cls):
    super(PemTestCase, cls).setUpClass()
    cls.user1 = User.objects.create(username='user1')
    cls.key1_path = os.path.join(cls.key_dir, 'key1')
    cls.key1_pem_path = os.path.join(cls.key_dir, 'key1.pem')
    ssh_keygen(comment='', file=cls.key1_path)
    ssh_key_export(cls.key1_path, cls.key1_pem_path, 'PEM')

  @classmethod
  def tearDownClass(cls):
    User.objects.all().delete()
    super(PemTestCase, cls).tearDownClass()

  def tearDown(self):
    UserKey.objects.all().delete()

  def test_import(self):
    key = UserKey(
      user=self.user1,
      name='name',
      key=open(self.key1_pem_path).read(),
    )
    key.full_clean()
    key.save()
    self.assertEqual(key.key.split()[:2],
                     open(self.key1_path + '.pub').read().split()[:2])

  def test_export(self):
    key = UserKey(
      user=self.user1,
      name='name',
      key=open(self.key1_path + '.pub').read(),
    )
    key.full_clean()
    key.save()
    export_path = os.path.join(self.key_dir, 'export')
    import_path = os.path.join(self.key_dir, 'import')
    with open(export_path, 'w') as f:
      f.write(key.export('PEM'))
    ssh_key_import(export_path, import_path, 'PEM')
    self.assertEqual(open(import_path).read().split()[:2],
                     open(self.key1_path + '.pub').read().split()[:2])


class UserKeyLookupTestCase(BaseTestCase):
  @classmethod
  def setUpClass(cls):
    super(UserKeyLookupTestCase, cls).setUpClass()
    cls.original_options = settings.SSHKEY_AUTHORIZED_KEYS_OPTIONS
    settings.SSHKEY_AUTHORIZED_KEYS_OPTIONS = 'command="{username} {key_id}"'
    cls.user1 = User.objects.create(username='user1')
    cls.user2 = User.objects.create(username='user2')

    # We force legacy fingerprints here because it is compatible with pre-6.8
    # OpenSSH and we can fake it in 6.8+ (see `ssh_fingerprint()`).
    default_hash = settings.SSHKEY_DEFAULT_HASH
    settings.SSHKEY_DEFAULT_HASH = 'legacy'

    cls.key1_path = os.path.join(cls.key_dir, 'key1')
    ssh_keygen(file=cls.key1_path)
    cls.key1 = UserKey(
      user=cls.user1,
      name='key1',
      key=open(cls.key1_path + '.pub').read(),
    )
    cls.key1.full_clean()
    cls.key1.save()

    cls.key2_path = os.path.join(cls.key_dir, 'key2')
    ssh_keygen(file=cls.key2_path)
    cls.key2 = UserKey(
      user=cls.user1,
      name='key2',
      key=open(cls.key2_path + '.pub').read(),
    )
    cls.key2.full_clean()
    cls.key2.save()

    cls.key3_path = os.path.join(cls.key_dir, 'key3')
    ssh_keygen(file=cls.key3_path)
    cls.key3 = UserKey(
      user=cls.user2,
      name='key3',
      key=open(cls.key3_path + '.pub').read(),
    )
    cls.key3.full_clean()
    cls.key3.save()
    settings.SSHKEY_DEFAULT_HASH = default_hash

  @classmethod
  def tearDownClass(cls):
    settings.SSHKEY_AUTHORIZED_KEYS_OPTIONS = cls.original_options
    User.objects.all().delete()
    super(UserKeyLookupTestCase, cls).tearDownClass()

  def assertHasKeys(self, response, keys):
    self.assertEqual(response.status_code, 200)
    self.assertIn('Content-Type', response)
    self.assertEqual(response['Content-Type'], 'text/plain')
    content = response.content.decode('ascii')
    actual = set(content.strip().splitlines())
    expected = set(keys)
    self.assertEqual(actual, expected)

  def test_lookup_all(self):
    url = reverse('django_sshkey.views.lookup')
    response = self.client.get(url)
    self.assertHasKeys(response, [
      'command="user1 %s" %s' % (
        self.key1.id,
        read_pubkey(self.key1_path + '.pub')
      ),
      'command="user1 %s" %s' % (
        self.key2.id,
        read_pubkey(self.key2_path + '.pub')
      ),
      'command="user2 %s" %s' % (
        self.key3.id,
        read_pubkey(self.key3_path + '.pub')
      ),
    ])

  def test_lookup_by_fingerprint(self):
    url = reverse('django_sshkey.views.lookup')
    fingerprint = ssh_fingerprint(self.key1_path + '.pub', hash='legacy')
    response = self.client.get(url, {'fingerprint': fingerprint})
    self.assertHasKeys(response, [
      'command="user1 %s" %s' % (
        self.key1.id,
        read_pubkey(self.key1_path + '.pub')
      ),
    ])

  def test_lookup_by_username_single_result(self):
    url = reverse('django_sshkey.views.lookup')
    username = self.user2.username
    response = self.client.get(url, {'username': username})
    self.assertHasKeys(response, [
      'command="user2 %s" %s' % (
        self.key3.id,
        read_pubkey(self.key3_path + '.pub')
      ),
    ])

  def test_lookup_by_username_multiple_results(self):
    url = reverse('django_sshkey.views.lookup')
    response = self.client.get(url, {'username': self.user1.username})
    self.assertHasKeys(response, [
      'command="user1 %s" %s' % (
        self.key1.id,
        open(self.key1_path + '.pub').read().strip()
      ),
      'command="user1 %s" %s' % (
        self.key2.id,
        open(self.key2_path + '.pub').read().strip()
      ),
    ])

  def test_lookup_nonexist_fingerprint(self):
    url = reverse('django_sshkey.views.lookup')
    fingerprint = ':'.join(['ff'] * 16)
    response = self.client.get(url, {'fingerprint': fingerprint})
    self.assertHasKeys(response, [])

  def test_lookup_nonexist_username(self):
    url = reverse('django_sshkey.views.lookup')
    response = self.client.get(url, {'username': 'batman'})
    self.assertHasKeys(response, [])


class FingerprintTestCase(BaseTestCase):
  @classmethod
  def setUpClass(cls):
    super(FingerprintTestCase, cls).setUpClass()
    cls.key_path = os.path.join(cls.key_dir, 'key1')
    cls.pubkey_path = cls.key_path + '.pub'
    ssh_keygen(comment='comment', file=cls.key_path)
    cls.pubkey = util.pubkey_parse(read_pubkey(cls.key_path + '.pub'))

  def test_fingerprint_legacy(self):
    '''Check legacy fingerprints'''
    expected = ssh_fingerprint(self.pubkey_path, hash='legacy')
    result = self.pubkey.fingerprint(hash='legacy')
    self.assertEqual(expected, result)

  @skipIf(SSH_VERSION < ('6', '8'),
          'OpenSSH 6.8+ required (%s found)' % SSH_VERSION_NAME)
  def test_fingerprint_md5(self):
    '''Matches OpenSSH's implementation of md5'''
    expected = ssh_fingerprint(self.pubkey_path, hash='md5')
    result = self.pubkey.fingerprint(hash='md5')
    self.assertEqual(expected, result)

  @skipIf(SSH_VERSION < ('6', '8'),
          'OpenSSH 6.8+ required (%s found)' % SSH_VERSION_NAME)
  def test_fingerprint_sha256(self):
    '''Matches OpenSSH's implementation of sha256'''
    expected = ssh_fingerprint(self.pubkey_path, hash='sha256')
    result = self.pubkey.fingerprint(hash='sha256')
    self.assertEqual(expected, result)

  def test_fingerprint_md5_prefix(self):
    '''Has MD5: prefix'''
    result = self.pubkey.fingerprint(hash='md5')
    self.assertTrue(result.startswith('MD5:'))

  def test_fingerprint_sha256_prefix(self):
    '''Has SHA256: prefix'''
    result = self.pubkey.fingerprint(hash='sha256')
    self.assertTrue(result.startswith('SHA256:'))

  def test_fingerprint_invalid_hash_name(self):
    '''Fails for bad hash names'''
    with self.assertRaises(ValueError) as cm:
      self.pubkey.fingerprint(hash='xxx')
    self.assertEqual('Unknown hash type: xxx', cm.exception.args[0])
