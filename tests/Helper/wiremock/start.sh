#!/bin/bash

# Adapted from @rowanhill wiremock start.sh script 
# https://github.com/rowanhill/wiremock-php/blob/master/wiremock/start.sh

cd ./tmp/

instance=1
port=8080
if [ $# -gt 0 ]; then
    instance=$1
    port=$2
fi
pidFile=wiremock.$instance.pid
logFile=wiremock.$instance.log

# Ensure WireMock isn't already running
if [ -e $pidFile ]; then
    echo WireMock is already started: see process `cat $pidFile` 1>&2
    exit 0
fi

# Download the wiremock jar if we need it
if ! [ -e wiremock-standalone.jar ]; then
    echo WireMock standalone JAR missing. Downloading.
    curl https://repo1.maven.org/maven2/com/github/tomakehurst/wiremock-jre8-standalone/2.32.0/wiremock-jre8-standalone-2.32.0.jar -o wiremock-standalone.jar
    status=$?
    if [ ${status} -ne 0 ]; then
        echo curl could not download WireMock JAR 1>&2
        exit ${status}
    fi
fi

# Start WireMock in standalone mode (in a background process) and save its output to a log
java -jar wiremock-standalone.jar --port $port --root-dir $instance --disable-banner &> $logFile 2>&1 &
pgrep -f wiremock-standalone.jar > $pidFile

echo WireMock $instance started on port $port