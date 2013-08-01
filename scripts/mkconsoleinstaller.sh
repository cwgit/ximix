#!/bin/bash
#
# Generate a mixnet console installer jar for one or more nodes using a gradle task
#

set -e   # Exit on any error
base=`/usr/bin/dirname $0`
cwd=`pwd`

mixnet=$cwd/$1

conf=$cwd/$2

cd $base/../


if [ -n "$1" ] && [ -n "$2" ]
then
    gradle clean jar make_console_installer "-Dmixnet=$mixnet" "-Dconfig=$conf"
else
    echo "Usage:  mkconsoleinstaller /path/to/mixnet.xml /path/to/console.xml"

fi
