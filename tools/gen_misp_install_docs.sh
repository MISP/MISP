#!/bin/bash

set -e
# set -x

if [ -e "$(which virtualenv)" ]; then
	echo "Python virtualenv exists, continuing with mkdocs build"
else
	echo "NO virtualenv present, bye."
  echo "sudo apt install virtualenv # Might help"
  exit 1
fi

if [ -z "$VIRTUAL_ENV" ]; then
  virtualenv -p python3 mkdocs || echo "You probably have the main Python(3) binary running exclusively somewhere, make sure it is killed."
  ${PWD}/mkdocs/bin/pip install mkdocs==1.0.4 mkdocs-material==4.6.3 markdown-include python-markdown-comments gitchangelog git+https://github.com/ryneeverett/python-markdown-comments.git
fi

[[ -e "$(which gsed)" ]] && xSED="gsed" || xSED="sed"

# Fixing ASCII aborration introduced in: https://github.com/MISP/MISP/commit/1b028ee15a3bd2f209102cd6204e6c4bb519be97
${PWD}/mkdocs/bin/gitchangelog |grep -v -e "  ,," -e "\.\.," > ../docs/Changelog.md
# Removing consecutive dupe lines
${PWD}/gen_misp_changelog.py

# For local testing, gitchangelog on large repos takes time.
#${PWD}/mkdocs/bin/gitchangelog > ../Changelog.txt
#cat ../Changelog.txt |grep -v -e "  ,," -e "\.\.," > ../docs/Changelog.md

# This search and replace is sub-optimal. It replaces 3 "~"s beginning of the line 
# and then just replaces the remaining 2 following tildes in the document. 
# This might change the sense of some commit messages...
${xSED} -i "s/^\~\~\~/---/" ../docs/Changelog.md
${xSED} -i "s/^- \#/- \\\#/" ../docs/Changelog.md
${xSED} -i "s/\~\~/--/g" ../docs/Changelog.md
${xSED} -i "s/%%version%%/v2.4 aka 2.4 for ever/g" ../docs/Changelog.md
${xSED} -i "s/\(unreleased\)/current changelog/g" ../docs/Changelog.md

# Emojifying things
${xSED} -i "s/\/\!\\\/:warning:/g" ../docs/Changelog.md
${xSED} -i "s/WiP/:construction:/g" ../docs/Changelog.md
${xSED} -i "s/WIP/:construction:/g" ../docs/Changelog.md
${xSED} -i "s/Wip:/:construction:/g" ../docs/Changelog.md
${xSED} -i "s/\[security\]/:lock:/g" ../docs/Changelog.md

## Other creative ways in sprinkling emoji goodness:
### Source: https://gist.github.com/pocotan001/68f96bf86891db316f20
#- :art:              when improving the format/structure of the code
#- :rocket:           when improving performance
#- :pencil2:          when writing docs
#- :bulb:             new idea
#- :construction:     work in progress
#- :heavy_plus_sign:  when adding feature
#- :heavy_minus_sign: when removing feature
#- :speaker:          when adding logging
#- :mute:             when reducing logging
#- :bug:              when fixing a bug
#- :white_check_mark: when adding tests
#- :lock:             when dealing with security
#- :arrow_up:         when upgrading dependencies
#- :arrow_down:       when downgrading dependencies

# Deploy mkdocs to gh-pages branch
cd ../ ; ${PWD}/tools/mkdocs/bin/mkdocs gh-deploy
