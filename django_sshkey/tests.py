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

from django.test import TestCase
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.urlresolvers import reverse
from django_sshkey.models import UserKey
from django_sshkey import settings
import os
import shutil
import subprocess
import tempfile


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


def ssh_fingerprint(pubkey_path):
  cmd = ['ssh-keygen', '-lf', pubkey_path]
  p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
  stdout, stderr = p.communicate()
  fingerprint = stdout.split(None, 2)[1]
  return fingerprint.decode('ascii')


def read_pubkey(path):
  '''Read an OpenSSH formatted public key'''
  return open(path).read().strip()


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

  def tearDown(self):
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

  def test_fingerprint(self):
    fingerprint = ssh_fingerprint(self.key1_path + '.pub')
    key = UserKey(
      user=self.user1,
      name='name',
      key=open(self.key1_path + '.pub').read(),
    )
    key.full_clean()
    key.save()
    self.assertEqual(key.fingerprint, fingerprint)

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

    cls.key4_path = os.path.join(cls.key_dir, 'key4')
    ssh_keygen(file=cls.key4_path)

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
    fingerprint = ssh_fingerprint(self.key1_path + '.pub')
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
    fingerprint = ssh_fingerprint(self.key4_path + '.pub')
    response = self.client.get(url, {'fingerprint': fingerprint})
    self.assertHasKeys(response, [])

  def test_lookup_nonexist_username(self):
    url = reverse('django_sshkey.views.lookup')
    response = self.client.get(url, {'username': 'batman'})
    self.assertHasKeys(response, [])
