#!/bin/bash

# Adapted from @rowanhill wiremock stop.sh script 
# https://github.com/rowanhill/wiremock-php/blob/master/wiremock/stop.sh

cd ./tmp/

instance=1
if [ $# -gt 0 ]; then
    instance=$1
fi
pidFile=wiremock.$instance.pid


if [ -e $pidFile ]; then
  kill -9 `cat $pidFile`
  rm $pidFile
else
  echo WireMock is not started 2>&1
fi

echo WireMock $instance stopped