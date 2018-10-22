#!/bin/bash

set -e
# set -x

if [ -e "/usr/bin/virtualenv" ]; then
	echo "Python virtualenv exists, continuing with mkdocs build"
else
	echo "NO virtualenv present, bye."
  exit 1
fi

if [ -z "$VIRTUAL_ENV" ]; then
    virtualenv -p python3 mkdocs
    ${PWD}/mkdocs/bin/pip install mkdocs mkdocs-material
fi
wget -O ../docs/Changelog.md https://www.misp-project.org/Changelog.txt
cd ../ ; ${PWD}/tools/mkdocs/bin/mkdocs gh-deploy
