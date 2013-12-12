#!/bin/bash
# Copyright 2013 Scott Duckworth
#
# This file is part of django-sshkey.
#
# django-sshkey is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# django-sshkey is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with django-sshkey.  If not, see <http://www.gnu.org/licenses/>.

url="$1"
if [ $# -eq 1 ]; then
  read line
  fingerprint=$(ssh-keygen -lf /dev/stdin <<< $line | cut -f2 -d' ')
  exec curl -s -G "$url" --data-urlencode "fingerprint=${fingerprint}"
elif [ $# -eq 2 ]; then
  username="$2"
  exec curl -s -G "$url" --data-urlencode "username=${username}"
else
  echo "Invalid number of arguments" >&2
  exit 2
fi
