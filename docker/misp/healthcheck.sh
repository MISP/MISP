#/usr/bin/env sh

set -e

MISP_READY_STATUS_FLAG='/tmp/.MISP_READY_STATUS_FLAG'

if [ ! -f "${MISP_READY_STATUS_FLAG}" ]; then
  exit 1
fi
