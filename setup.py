import os
from setuptools import setup

README = open(os.path.join(os.path.dirname(__file__), 'README.md')).read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

execfile('django_sshkey/__init__.py')

setup(
  name='django-sshkey',
  version=__version__,
  packages=['django_sshkey'],
  include_package_data=True,
  license='GNU Lesser General Public License v3 (LGPLv3)',
  description='A Django app to identify users by their SSH public keys.',
  long_description=README,
  url='https://bitbucket.org/ClemsonSoCUnix/django-sshkey',
  author='Scott Duckworth',
  author_email='sduckwo@clemson.edu',
  classifiers=[
    'Environment :: Web Environment',
    'Framework :: Django',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)',
    'Operating System :: OS Independent',
    'Programming Language :: Python',
    'Programming Language :: Python :: 2.6',
    'Programming Language :: Python :: 2.7',
    'Topic :: Internet :: WWW/HTTP',
    'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
  ],
  scripts=[
    'django-sshkey-lookup',
  ],
  entry_points={
    'console_scripts': [
      'django-sshkey-pylookup = django_sshkey.util:lookup_main',
    ],
  },
)
