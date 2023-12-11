#!/bin/bash
if [ ! -d ./app/Lib/cakephp/app ]
then
    echo "CakePHP has not been pulled."
    echo "Make sure all submodules are intialized and updated. Please run:"
    echo "git submodule init"
    echo "git submodule update"
    exit 1
fi

dpkg-buildpackage -b -rfakeroot -us -uc

