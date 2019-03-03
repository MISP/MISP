#!/usr/bin/env bash

# TODO: Improve script to bring workers up that are not.

# Extract base directory where this script is and cd into it
cd "${0%/*}"

# Check if run as root
if [ "$EUID" -eq 0 ]; then
    echo "Please DO NOT run the worker script as root"
    exit 1
fi

##[[ $(../cake CakeResque.CakeResque stop --all |grep "not permitted" ; echo $?) != 1 ]] && echo "Either you have no permissions or CakeResque is not installed/configured" && exit 1

## FIXME: PIDs seem off by 1
# Check which workers are currently running
WORKERS_PID=$(ps a |grep CakeResque |grep -v grep |cut -f 1 -d\ )

if [[ ! -z $WORKERS_PID ]]; then
  for p in $WORKERS_PID; do
    WORKER_RUNNING=$(ps $p |grep CakeRes|grep -v grep |grep -o -e "QUEUE=.[a-z]*" |cut -f2 -d\')
    #echo "Worker $WORKER_RUNNING with PID $p"
  done
fi

../cake CakeResque.CakeResque stop --all
../cake CakeResque.CakeResque start --interval 5 --queue default
../cake CakeResque.CakeResque start --interval 5 --queue prio
../cake CakeResque.CakeResque start --interval 5 --queue cache
../cake CakeResque.CakeResque start --interval 5 --queue email
../cake CakeResque.CakeResque startscheduler --interval 5

exit 0
