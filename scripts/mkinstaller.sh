#!/bin/bash
#
# Generate a mixnet installer jar for one or more nodes using a gradle task
#

set -e   # Exit on any error
base=`/usr/bin/dirname $0`
cwd=`pwd`

mixnet=$cwd/$1

while shift
do
    if [ -n "$1" ]
    then
        node=`echo $node,$cwd/$1`
    fi
done

cd $base

if [ -n "$mixnet" ]
then
    gradle clean jar make_node_installer "-Dnetwork=$mixnet$node"
else
    echo "Confirm generation of a basic installer with NO inbuilt configuration: [No]"
    read conf

    case $conf in
    y*|Y*)
        gradle clean jar make_node_installer
        ;;
    esac
fi
