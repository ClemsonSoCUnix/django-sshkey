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
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os
from setuptools import setup

README = open(os.path.join(os.path.dirname(__file__), 'README.rst')).read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

exec(open('django_sshkey/__init__.py').read())

setup(
  name='django-sshkey',
  version=__version__,
  packages=['django_sshkey'],
  include_package_data=True,
  license='BSD',
  description='Associates multiple SSH public keys with Django user accounts.',
  long_description=README,
  url='https://github.com/ClemsonSoCUnix/django-sshkey',
  author='Scott Duckworth',
  author_email='sduckwo@clemson.edu',
  zip_safe=False,
  classifiers=[
    'Environment :: Web Environment',
    'Framework :: Django',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: BSD License',
    'Operating System :: OS Independent',
    'Programming Language :: Python',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3.3',
    'Programming Language :: Python :: 3.4',
    'Topic :: Internet :: WWW/HTTP',
    'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
  ],
  scripts=[
    'django-sshkey-lookup',
    'django-sshkey-lookup-all',
    'django-sshkey-lookup-by-username',
    'django-sshkey-lookup-by-fingerprint',
  ],
  entry_points={
    'console_scripts': [
      'django-sshkey-pylookup = django_sshkey.util:lookup_main',
      'django-sshkey-pylookup-all = django_sshkey.util:lookup_all_main',
      'django-sshkey-pylookup-by-username = django_sshkey.util:lookup_by_username_main',
      'django-sshkey-pylookup-by-fingerprint = django_sshkey.util:lookup_by_fingerprint_main',
    ],
  },
  install_requires = [
    'pyasn1',
  ],
)
