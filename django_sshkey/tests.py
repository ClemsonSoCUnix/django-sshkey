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
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.core.urlresolvers import reverse
from django_sshkey.forms import UserKeyForm
from django_sshkey.models import Key, ApplicationKey, NamedKey, UserKey
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
  return fingerprint

class TestApplicationKey(ApplicationKey):
  pass

class TestNamedKey(NamedKey):
  pass

class BaseTestCase(TestCase):
  @classmethod
  def setUpClass(cls):
    cls.key_dir = tempfile.mkdtemp(prefix='sshkey-test.')

  @classmethod
  def tearDownClass(cls):
    if cls.key_dir:
      shutil.rmtree(cls.key_dir)
      cls.key_dir = None

class KeyCreationTestCase(BaseTestCase):
  @classmethod
  def setUpClass(cls):
    super(KeyCreationTestCase, cls).setUpClass()
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
    super(KeyCreationTestCase, cls).tearDownClass()

  def tearDown(self):
    Key.objects.all().delete()

  def test_private_key_fails(self):
    key = Key(
      key = open(self.key1_path).read(),
    )
    self.assertRaises(ValidationError, key.full_clean)

  def test_invalid_key_fails(self):
    key = Key(
      key = 'ssh-rsa invalid',
    )
    self.assertRaises(ValidationError, key.full_clean)

  def test_key_with_options_fails(self):
    key = Key(
      key = 'command="foobar" ' + open(self.key1_path+'.pub').read(),
    )
    self.assertRaises(ValidationError, key.full_clean)

  def test_multiple_keys_fails(self):
    key = Key(
      key = open(self.key1_path+'.pub').read() \
          + open(self.key2_path+'.pub').read(),
    )
    self.assertRaises(ValidationError, key.full_clean)

  def test_fingerprint(self):
    fingerprint = ssh_fingerprint(self.key1_path+'.pub')
    key = Key(
      key = open(self.key1_path+'.pub').read(),
    )
    key.full_clean()
    self.assertEqual(key.fingerprint, fingerprint)

  def test_touch(self):
    import datetime
    key = Key(
      content_type = ContentType.objects.get_for_model(Key),  # to satisfy foreign key
      key = open(self.key1_path+'.pub').read(),
    )
    key.full_clean()
    self.assertIsNone(key.last_used)
    key.touch()
    self.assertIsInstance(key.last_used, datetime.datetime)
    key.touch()

  def test_blank_key_fails(self):
    key = Key(
      key = '',
    )
    self.assertRaises(ValidationError, key.full_clean)

  def test_ws_key_fails(self):
    key = Key(
      key = '     ',
    )
    self.assertRaises(ValidationError, key.full_clean)

  def test_unicode1(self):
    '''With fingerprint.'''
    key = Key(
      key = open(self.key1_path + '.pub').read()
    )
    key.full_clean()
    self.assertEqual(key.fingerprint, unicode(key))

  def test_unicode2(self):
    '''Without fingerprint.'''
    contents = open(self.key1_path + '.pub').read()
    key = Key(key=contents)
    self.assertEqual(contents[:20] + '...', unicode(key))

class ApplicationKeyTestCase(BaseTestCase):
  @classmethod
  def setUpClass(cls):
    super(ApplicationKeyTestCase, cls).setUpClass()
    # key1 has a comment
    cls.key1_path = os.path.join(cls.key_dir, 'key1')
    ssh_keygen(comment='comment', file=cls.key1_path)
    cls.key1 = TestApplicationKey.base(key=open(cls.key1_path + '.pub').read())
    cls.key1.full_clean()
    cls.key1.save()
    cls.app_key1 = TestApplicationKey(basekey=cls.key1)
    cls.app_key1.save()

  @classmethod
  def tearDownClass(cls):
    Key.objects.all().delete()
    super(ApplicationKeyTestCase, cls).tearDownClass()

  def test_key_attribute(self):
    self.assertEqual(self.key1.key, self.app_key1.key)

  def test_fingerprint_attribute(self):
    self.assertEqual(self.key1.fingerprint, self.app_key1.fingerprint)

  def test_created_attribute(self):
    self.assertEqual(self.key1.created, self.app_key1.created)

  def test_last_modified_attribute(self):
    self.assertEqual(self.key1.last_modified, self.app_key1.last_modified)

  def test_last_used_attribute(self):
    self.assertEqual(self.key1.last_used, self.app_key1.last_used)

  def test_unicode1(self):
    ''' No basekey '''
    key = TestApplicationKey()
    self.assertEqual('(no basekey)', unicode(key))

  def test_unicode2(self):
    ''' With basekey '''
    self.assertEqual(unicode(self.key1), unicode(self.app_key1))

class NamedKeyTestCase(BaseTestCase):
  @classmethod
  def setUpClass(cls):
    super(NamedKeyTestCase, cls).setUpClass()
    # key1 has a comment
    cls.key1_path = os.path.join(cls.key_dir, 'key1')
    ssh_keygen(comment='comment', file=cls.key1_path)
    cls.key1 = Key(key=open(cls.key1_path + '.pub').read())
    cls.key1.full_clean()
    cls.key1.save()

    # key2 does not have a comment
    cls.key2_path = os.path.join(cls.key_dir, 'key2')
    ssh_keygen(comment='', file=cls.key2_path)
    cls.key2 = Key(key=open(cls.key2_path + '.pub').read())
    cls.key2.full_clean()
    cls.key2.save()

  def test_with_name_with_comment(self):
    key = TestNamedKey(
      name = 'name',
      basekey = self.key1,
    )
    key.full_clean()
    key.save()
    self.assertEqual(key.name, 'name')

  def test_with_name_without_comment(self):
    key = TestNamedKey(
      name = 'name',
      basekey = self.key2,
    )
    key.full_clean()
    key.save()
    self.assertEqual(key.name, 'name')

  def test_without_name_with_comment(self):
    key = TestNamedKey(
      basekey = self.key1,
    )
    key.full_clean()
    key.save()
    self.assertEqual(key.name, 'comment')

  def test_without_name_without_comment_fails(self):
    key = TestNamedKey(
      basekey = self.key2,
    )
    self.assertRaises(ValidationError, key.full_clean)

  def test_unicode(self):
    key = TestNamedKey(basekey=self.key1)
    key.full_clean()
    key.save()
    self.assertEqual(key.name, unicode(key))

class UserKeyTestCase(BaseTestCase):
  @classmethod
  def setUpClass(cls):
    super(UserKeyTestCase, cls).setUpClass()
    cls.user1 = User.objects.create(username='user1')
    cls.user2 = User.objects.create(username='user2')

    # key1 has a comment
    cls.key1_path = os.path.join(cls.key_dir, 'key1')
    ssh_keygen(comment='comment', file=cls.key1_path)

    # key2 does not have a comment
    cls.key2_path = os.path.join(cls.key_dir, 'key2')
    ssh_keygen(comment='', file=cls.key2_path)

    # key3 is safe to delete
    cls.key3_path = os.path.join(cls.key_dir, 'key3')
    ssh_keygen(comment='comment', file=cls.key3_path)

    # make the Key models
    cls.key1 = Key(key=open(cls.key1_path + '.pub').read())
    cls.key1.full_clean()
    cls.key1.save()
    cls.key2 = Key(key=open(cls.key2_path + '.pub').read())
    cls.key2.full_clean()
    cls.key2.save()

  @classmethod
  def tearDownClass(cls):
    User.objects.all().delete()
    super(UserKeyTestCase, cls).tearDownClass()

  def test_same_name_same_user(self):
    key1 = UserKey(
      user = self.user1,
      name = 'name',
      basekey = self.key1,
    )
    key1.full_clean()
    key1.save()
    key2 = UserKey(
      user = self.user1,
      name = 'name',
      key = open(self.key2_path+'.pub').read(),
      basekey = self.key2,
    )
    self.assertRaises(ValidationError, key2.full_clean)

  def test_same_name_different_user(self):
    key1 = UserKey(
      user = self.user1,
      name = 'name',
      basekey = self.key1,
    )
    key1.full_clean()
    key1.save()
    key2 = UserKey(
      user = self.user2,
      name = 'name',
      basekey = self.key2,
    )
    key2.full_clean()
    key2.save()

  def test_same_key_same_user(self):
    key1 = UserKey(
      user = self.user1,
      name = 'name1',
      basekey = self.key1,
    )
    key1.full_clean()
    key1.save()
    key2 = UserKey(
      user = self.user1,
      name = 'name2',
      basekey = self.key1,
    )
    self.assertRaises(ValidationError, key2.full_clean)

  def test_same_key_different_user(self):
    key1 = UserKey(
      basekey = self.key1,
      user = self.user1,
      name = 'name1',
    )
    key1.full_clean()
    key1.save()
    key2 = UserKey(
      basekey = self.key1,
      user = self.user2,
      name = 'name2',
    )
    self.assertRaises(ValidationError, key2.full_clean)

  def test_delete(self):
    basekey = Key(key=open(self.key3_path + '.pub').read())
    basekey.full_clean()
    basekey.save()
    pk = basekey.pk

    key1 = UserKey(basekey=basekey, user=self.user1, name='name1')
    key1.full_clean()
    key1.save()
    key1.delete()
    self.assertRaises(Key.DoesNotExist, Key.objects.get, pk=pk)

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
    Key.objects.all().delete()

  def test_import_with_comment(self):
    key = Key(
      #user = self.user1,
      #name = 'name',
      key = open(self.key1_rfc4716_path).read(),
    )
    key.full_clean()
    key.save()
    self.assertEqual(key.key.split()[:2], open(self.key1_path+'.pub').read().split()[:2])

  def test_import_without_comment(self):
    key = Key(
      #user = self.user1,
      #name = 'name',
      key = open(self.key2_rfc4716_path).read(),
    )
    key.full_clean()
    key.save()
    self.assertEqual(key.key.split()[:2], open(self.key2_path+'.pub').read().split()[:2])

  def test_export(self):
    key = Key(
      #user = self.user1,
      #name = 'name',
      key = open(self.key1_path+'.pub').read(),
    )
    key.full_clean()
    key.save()
    export_path = os.path.join(self.key_dir, 'export')
    import_path = os.path.join(self.key_dir, 'import')
    with open(export_path, 'w') as f:
      f.write(key.export('RFC4716'))
    ssh_key_import(export_path, import_path, 'RFC4716')
    self.assertEqual(open(import_path).read().split()[:2], open(self.key1_path+'.pub').read().split()[:2])

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
    Key.objects.all().delete()

  def test_import(self):
    key = Key(
      #user = self.user1,
      #name = 'name',
      key = open(self.key1_pem_path).read(),
    )
    key.full_clean()
    key.save()
    self.assertEqual(key.key.split()[:2], open(self.key1_path+'.pub').read().split()[:2])

  def test_export(self):
    key = Key(
      #user = self.user1,
      #name = 'name',
      key = open(self.key1_path+'.pub').read(),
    )
    key.full_clean()
    key.save()
    export_path = os.path.join(self.key_dir, 'export')
    import_path = os.path.join(self.key_dir, 'import')
    with open(export_path, 'w') as f:
      f.write(key.export('PEM'))
    ssh_key_import(export_path, import_path, 'PEM')
    self.assertEqual(open(import_path).read().split()[:2], open(self.key1_path+'.pub').read().split()[:2])

class KeyLookupTestCase(BaseTestCase):
  @classmethod
  def setUpClass(cls):
    super(KeyLookupTestCase, cls).setUpClass()
    cls.original_options = settings.SSHKEY_AUTHORIZED_KEYS_OPTIONS
    settings.SSHKEY_AUTHORIZED_KEYS_OPTIONS = 'command="{username} {key_id}"'
    cls.user1 = User.objects.create(username='user1')
    cls.user2 = User.objects.create(username='user2')

    def generate_key(name, user):
      path = os.path.join(cls.key_dir, name)
      ssh_keygen(file=path)
      key = UserKey.base(key=open(path + '.pub').read())
      key.full_clean()
      key.save()
      userkey = UserKey(basekey=key, name=name, user=user)
      userkey.full_clean()
      userkey.save()
      return path, key, userkey

    cls.key1_path, cls.key1, cls.userkey1 = generate_key('key1', cls.user1)
    cls.key2_path, cls.key2, cls.userkey2 = generate_key('key2', cls.user1)
    cls.key3_path, cls.key3, cls.userkey3 = generate_key('key3', cls.user2)

    cls.key4_path = os.path.join(cls.key_dir, 'key4')
    ssh_keygen(file=cls.key4_path)

  @classmethod
  def tearDownClass(cls):
    settings.SSHKEY_AUTHORIZED_KEYS_OPTIONS = cls.original_options
    User.objects.all().delete()
    Key.objects.all().delete()
    UserKey.objects.all().delete()
    super(KeyLookupTestCase, cls).tearDownClass()

  def test_lookup_all(self):
    client = Client()
    url = reverse('django_sshkey.views.lookup')
    response = client.get(url)
    self.assertEqual(response.status_code, 200)
    self.assertIn('Content-Type', response)
    self.assertEqual(response['Content-Type'], 'text/plain')
    actual_content = set(response.content.strip().split('\n'))
    correct_content = set((
      'command="user1 %s" %s' % (self.key1.id, open(self.key1_path + '.pub').read().strip()),
      'command="user1 %s" %s' % (self.key2.id, open(self.key2_path + '.pub').read().strip()),
      'command="user2 %s" %s' % (self.key3.id, open(self.key3_path + '.pub').read().strip()),
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
      'command="user1 %s" %s' % (self.key1.id, open(self.key1_path + '.pub').read().strip()),
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
      'command="user2 %s" %s' % (self.key3.id, open(self.key3_path + '.pub').read().strip()),
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
      'command="user1 %s" %s' % (self.key1.id, open(self.key1_path + '.pub').read().strip()),
      'command="user1 %s" %s' % (self.key2.id, open(self.key2_path + '.pub').read().strip()),
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

class UserKeyFormTestCase(BaseTestCase):
  @classmethod
  def setUpClass(cls):
    super(UserKeyFormTestCase, cls).setUpClass()
    cls.user1 = User.objects.create(username='user1')
    cls.key1_path = os.path.join(cls.key_dir, 'key1')
    ssh_keygen(comment='comment', file=cls.key1_path)

  @classmethod
  def tearDownClass(cls):
    cls.user1.delete()
    super(UserKeyFormTestCase, cls).tearDownClass()

  def test_save_without_name(self):
    instance = UserKey(user=self.user1)
    post = {
      'key': open(self.key1_path + '.pub').read(),
    }
    form = UserKeyForm(post, instance=instance)
    self.assertTrue(form.is_valid(), form.errors)
    key = form.save()
    self.assertEqual('comment', key.name)

  def test_save_with_name(self):
    instance = UserKey(user=self.user1)
    post = {
      'key': open(self.key1_path + '.pub').read(),
      'name': 'name',
    }
    form = UserKeyForm(post, instance=instance)
    self.assertTrue(form.is_valid(), form.errors)
    key = form.save()
    self.assertEqual('name', key.name)

  def test_save_blank_name(self):
    instance = UserKey(user=self.user1)
    post = {
      'key': open(self.key1_path + '.pub').read(),
      'name': '',
    }
    form = UserKeyForm(post, instance=instance)
    self.assertTrue(form.is_valid(), form.errors)
    key = form.save()
    self.assertEqual('comment', key.name)
