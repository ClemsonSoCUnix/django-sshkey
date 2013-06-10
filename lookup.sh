#!/bin/bash

url="$1"
if [ $# -eq 1 ]; then
  read line
  fingerprint=$(ssh-keygen -lf /dev/stdin <<< $line | cut -f2 -d' ')
  exec curl -G "$url" --data-urlencode "fingerprint=${fingerprint}"
elif [ $# -eq 2 ]; then
  username="$2"
  exec curl -G "$url" --data-urlencode "username=${username}"
else
  echo "Invalid number of arguments" >&2
  exit 2
fi
