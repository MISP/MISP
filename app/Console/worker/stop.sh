#!/usr/bin/env bash

# TODO: Put some logic inside if many worker PIDs are detected

# Extract base directory where this script is and cd into it
cd "${0%/*}"

# Set to the current webroot owner
WWW_USER=$(ls -l ../cake |awk {'print $3'}|tail -1)

# In most cases the owner of the cake script is also the user as which it should be executed.
if [[ "$USER" != "$WWW_USER" ]]; then
  echo "You run this script as $USER and the owner of the cake command is $WWW_USER. This might be an issue."
fi

# Check if run as root
if [[ "$EUID" -eq "0" ]]; then
    echo "Please DO NOT run the worker script as root"
    exit 1
fi

../cake CakeResque.CakeResque stop --all
