# Stupid script to fetch MISP's install files including submodules and composer sourced libraries

# This is currently a relative path, highly recommended to replace with an absolute path
# For example, if you want the fetcher to work in /foo/bar/baz, use "/foo/bar/baz/MISPflat"
MISP_FLAT_ROOT="MISPflat"

git clone https://github.com/MISP/MISP.git $MISP_FLAT_ROOT
cd $MISP_FLAT_ROOT
git submodule update --init --recursive
cd ..
cd $MISP_FLAT_ROOT/app
composer install --no-dev
cd ../..
cd $MISP_FLAT_ROOT
zip -r ../misp_flat.zip .
cd ..
rm -rf $MISP_FLAT_ROOT

