#!/usr/bin/env bash

# Check if run as root
if [ "$EUID" -eq 0 ]; then
    echo "Please DO NOT run the worker script as root"
    exit 1
fi

# Extract base directory where this script is and cd into it
cd "${0%/*}"
../cake CakeResque.CakeResque stop --all
../cake CakeResque.CakeResque start --interval 5 --queue default
../cake CakeResque.CakeResque start --interval 5 --queue prio
../cake CakeResque.CakeResque start --interval 5 --queue cache
../cake CakeResque.CakeResque start --interval 5 --queue email
../cake CakeResque.CakeResque startscheduler --interval 5

exit 0
