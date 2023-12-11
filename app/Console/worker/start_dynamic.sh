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

# Check if jq is present and enable advanced checks
if [[ "$(jq -V > /dev/null 2> /dev/null; echo $?)" != 0 ]]; then
  echo "jq is not installed, disabling advanced checks."
  ADVANCED="0"
else
  ADVANCED="1"
fi

if [[ "$ADVANCED" == "1" ]]; then
  for worker in `echo cache default email prio scheduler update`; do
    workerStatus=$(../cake Admin getWorkers |tail -n +7 |jq  -r ".$worker" |jq -r '.ok')
    PIDcount=$(../cake admin getWorkers |tail -n +7 |jq -r ".$worker.workers" |grep pid | wc -l)
    echo -n "$worker has $PIDcount PID(s)"
    if [[ "$workerStatus" != "true" ]]; then
      echo ", trying to restart."
      if [[ "$worker" != "scheduler" ]]; then
        ../cake CakeResque.CakeResque start --interval 5 --queue $worker
      else
        ../cake CakeResque.CakeResque startscheduler --interval 5
      fi
    else
      echo ", up and running."
    fi
  done
  exit 0
else

  ../cake CakeResque.CakeResque stop --all
  ../cake CakeResque.CakeResque start --interval 5 --queue default
  ../cake CakeResque.CakeResque start --interval 5 --queue prio
  ../cake CakeResque.CakeResque start --interval 5 --queue cache
  ../cake CakeResque.CakeResque start --interval 5 --queue email
  ../cake CakeResque.CakeResque start --interval 5 --queue update
  ../cake CakeResque.CakeResque startscheduler --interval 5

  exit 0
fi
