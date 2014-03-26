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

from django.test import TestCase
from django.test.client import Client
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

def ssh_fingerprint(pubkey_path):
  cmd = ['ssh-keygen', '-lf', pubkey_path]
  p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
  stdout, stderr = p.communicate()
  fingerprint = stdout.split(None, 2)[1]
  return fingerprint

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
      user = self.user1,
      name = 'name',
      key = open(self.key1_path+'.pub').read(),
    )
    key.full_clean()
    key.save()
    self.assertEqual(key.name, 'name')

  def test_with_name_without_comment(self):
    key = UserKey(
      user = self.user1,
      name = 'name',
      key = open(self.key2_path+'.pub').read(),
    )
    key.full_clean()
    key.save()
    self.assertEqual(key.name, 'name')

  def test_without_name_with_comment(self):
    key = UserKey(
      user = self.user1,
      key = open(self.key1_path+'.pub').read(),
    )
    key.full_clean()
    key.save()
    self.assertEqual(key.name, 'comment')

  def test_without_name_without_comment_fails(self):
    key = UserKey(
      user = self.user1,
      key = open(self.key2_path+'.pub').read(),
    )
    self.assertRaises(ValidationError, key.full_clean)

  def test_private_key_fails(self):
    key = UserKey(
      user = self.user1,
      name = 'name',
      key = open(self.key1_path).read(),
    )
    self.assertRaises(ValidationError, key.full_clean)

  def test_invalid_key_fails(self):
    key = UserKey(
      user = self.user1,
      name = 'name',
      key = 'ssh-rsa invalid',
    )
    self.assertRaises(ValidationError, key.full_clean)

  def test_key_with_options_fails(self):
    key = UserKey(
      user = self.user1,
      name = 'name',
      key = 'command="foobar" ' + open(self.key1_path+'.pub').read(),
    )
    self.assertRaises(ValidationError, key.full_clean)

  def test_multiple_keys_fails(self):
    key = UserKey(
      user = self.user1,
      name = 'name',
      key = open(self.key1_path+'.pub').read() \
          + open(self.key2_path+'.pub').read(),
    )
    self.assertRaises(ValidationError, key.full_clean)

  def test_fingerprint(self):
    fingerprint = ssh_fingerprint(self.key1_path+'.pub')
    key = UserKey(
      user = self.user1,
      name = 'name',
      key = open(self.key1_path+'.pub').read(),
    )
    key.full_clean()
    key.save()
    self.assertEqual(key.fingerprint, fingerprint)

  def test_same_name_same_user(self):
    key1 = UserKey(
      user = self.user1,
      name = 'name',
      key = open(self.key1_path+'.pub').read(),
    )
    key1.full_clean()
    key1.save()
    key2 = UserKey(
      user = self.user1,
      name = 'name',
      key = open(self.key2_path+'.pub').read(),
    )
    self.assertRaises(ValidationError, key2.full_clean)

  def test_same_name_different_user(self):
    key1 = UserKey(
      user = self.user1,
      name = 'name',
      key = open(self.key1_path+'.pub').read(),
    )
    key1.full_clean()
    key1.save()
    key2 = UserKey(
      user = self.user2,
      name = 'name',
      key = open(self.key2_path+'.pub').read(),
    )
    key2.full_clean()
    key2.save()

  def test_same_key_same_user(self):
    key1 = UserKey(
      user = self.user1,
      name = 'name1',
      key = open(self.key1_path+'.pub').read(),
    )
    key1.full_clean()
    key1.save()
    key2 = UserKey(
      user = self.user1,
      name = 'name2',
      key = open(self.key1_path+'.pub').read(),
    )
    self.assertRaises(ValidationError, key2.full_clean)

  def test_same_key_different_user(self):
    key1 = UserKey(
      user = self.user1,
      name = 'name1',
      key = open(self.key1_path+'.pub').read(),
    )
    key1.full_clean()
    key1.save()
    key2 = UserKey(
      user = self.user2,
      name = 'name2',
      key = open(self.key1_path+'.pub').read(),
    )
    self.assertRaises(ValidationError, key2.full_clean)

class UserKeyLookupTestCase(BaseTestCase):
  @classmethod
  def setUpClass(cls):
    super(UserKeyLookupTestCase, cls).setUpClass()
    cls.original_options = settings.SSHKEY_AUTHORIZED_KEYS_OPTIONS
    settings.SSHKEY_AUTHORIZED_KEYS_OPTIONS = 'command="{username}"'
    cls.user1 = User.objects.create(username='user1')
    cls.user2 = User.objects.create(username='user2')

    cls.key1_path = os.path.join(cls.key_dir, 'key1')
    ssh_keygen(file=cls.key1_path)
    key1 = UserKey(
      user = cls.user1,
      name = 'key1',
      key = open(cls.key1_path+'.pub').read(),
    )
    key1.full_clean()
    key1.save()

    cls.key2_path = os.path.join(cls.key_dir, 'key2')
    ssh_keygen(file=cls.key2_path)
    key2 = UserKey(
      user = cls.user1,
      name = 'key2',
      key = open(cls.key2_path+'.pub').read(),
    )
    key2.full_clean()
    key2.save()

    cls.key3_path = os.path.join(cls.key_dir, 'key3')
    ssh_keygen(file=cls.key3_path)
    key3 = UserKey(
      user = cls.user2,
      name = 'key3',
      key = open(cls.key3_path+'.pub').read(),
    )
    key3.full_clean()
    key3.save()

    cls.key4_path = os.path.join(cls.key_dir, 'key4')
    ssh_keygen(file=cls.key4_path)

  @classmethod
  def tearDownClass(cls):
    settings.SSHKEY_AUTHORIZED_KEYS_OPTIONS = cls.original_options
    User.objects.all().delete()
    super(UserKeyLookupTestCase, cls).tearDownClass()

  def test_lookup_all(self):
    client = Client()
    url = reverse('django_sshkey.views.lookup')
    response = client.get(url)
    self.assertEqual(response.status_code, 200)
    self.assertIn('Content-Type', response)
    self.assertEqual(response['Content-Type'], 'text/plain')
    actual_content = set(response.content.strip().split('\n'))
    correct_content = set((
      'command="user1" ' + open(self.key1_path + '.pub').read().strip(),
      'command="user1" ' + open(self.key2_path + '.pub').read().strip(),
      'command="user2" ' + open(self.key3_path + '.pub').read().strip(),
    ))
    self.assertEqual(actual_content, correct_content)

  def test_lookup_by_fingerprint(self):
    client = Client()
    url = reverse('django_sshkey.views.lookup')
    fingerprint = ssh_fingerprint(self.key1_path+'.pub')
    response = client.get(url, {'fingerprint': fingerprint})
    self.assertEqual(response.status_code, 200)
    self.assertIn('Content-Type', response)
    self.assertEqual(response['Content-Type'], 'text/plain')
    username = self.user1.username
    actual_content = set(response.content.strip().split('\n'))
    correct_content = set((
      'command="user1" ' + open(self.key1_path + '.pub').read().strip(),
    ))
    self.assertEqual(actual_content, correct_content)

  def test_lookup_by_username_single_result(self):
    client = Client()
    url = reverse('django_sshkey.views.lookup')
    username = self.user2.username
    response = client.get(url, {'username': username})
    self.assertEqual(response.status_code, 200)
    self.assertIn('Content-Type', response)
    self.assertEqual(response['Content-Type'], 'text/plain')
    body = open(self.key1_path + '.pub').read().strip()
    actual_content = set(response.content.strip().split('\n'))
    correct_content = set((
      'command="user2" ' + open(self.key3_path + '.pub').read().strip(),
    ))
    self.assertEqual(actual_content, correct_content)

  def test_lookup_by_username_multiple_results(self):
    client = Client()
    url = reverse('django_sshkey.views.lookup')
    username = self.user1.username
    response = client.get(url, {'username': username})
    self.assertEqual(response.status_code, 200)
    self.assertIn('Content-Type', response)
    self.assertEqual(response['Content-Type'], 'text/plain')
    body = open(self.key1_path + '.pub').read().strip()
    actual_content = set(response.content.strip().split('\n'))
    correct_content = set((
      'command="user1" ' + open(self.key1_path + '.pub').read().strip(),
      'command="user1" ' + open(self.key2_path + '.pub').read().strip(),
    ))
    self.assertEqual(actual_content, correct_content)

  def test_lookup_nonexist_fingerprint(self):
    client = Client()
    url = reverse('django_sshkey.views.lookup')
    fingerprint = ssh_fingerprint(self.key4_path+'.pub')
    response = client.get(url, {'fingerprint': fingerprint})
    self.assertEqual(response.status_code, 200)
    self.assertIn('Content-Type', response)
    self.assertEqual(response['Content-Type'], 'text/plain')
    self.assertEqual(response.content, '')

  def test_lookup_nonexist_username(self):
    client = Client()
    url = reverse('django_sshkey.views.lookup')
    response = client.get(url, {'username': 'batman'})
    self.assertEqual(response.status_code, 200)
    self.assertIn('Content-Type', response)
    self.assertEqual(response['Content-Type'], 'text/plain')
    self.assertEqual(response.content, '')
