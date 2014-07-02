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

from django.conf import settings

SSHKEY_AUTHORIZED_KEYS_OPTIONS = getattr(settings, 'SSHKEY_AUTHORIZED_KEYS_OPTIONS', None)
SSHKEY_EMAIL_ADD_KEY = getattr(settings, 'SSHKEY_EMAIL_ADD_KEY', True)
SSHKEY_EMAIL_ADD_KEY_SUBJECT = getattr(settings, 'SSHKEY_EMAIL_ADD_KEY_SUBJECT',
  "A new public key was added to your account"
)
SSHKEY_EMAIL_ADD_KEY_BODY = getattr(settings, 'SSHKEY_EMAIL_ADD_KEY_BODY',
  "{user_first_name},\n\n"
  "The following SSH public key was added to your account from {remote_addr}:\n\n"
  "{key_name}\n"
  "{key_fingerprint}\n\n"
  "If you believe this key was added in error, you should delete the key."
)
DEFAULT_FROM_EMAIL = settings.DEFAULT_FROM_EMAIL
