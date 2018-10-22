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
# This search and replace is sub-optimal. It replaces 3 "~"s beginning of the line 
# and then just replaces the remaining 2 following tildes in the document. 
# This might change the sense of some commit messages...
sed -i "s/^\~\~\~/---/" ../docs/Changelog.md
sed -i "s/\~\~/--/g" ../docs/Changelog.md

# Deploy mkdocs to gh-pages branch
cd ../ ; ${PWD}/tools/mkdocs/bin/mkdocs gh-deploy
