#!/bin/bash

if [[ -z "$XIMXI_HOME" ]]; then
	L=`dirname $0`
	XIMIX_HOME="$L/../"
	 
fi

if [[ ! -f "$XIMIX_HOME/libs/node.jar" ]]; then
	echo "Could not find libs/node.jar off XIMIX_HOME ( $XIMIX_HOME )"
	exit -1
fi


if [[ -z "$JAVA_HOME" ]]; then
     	echo "JAVA_HOME is not specified";  
fi


if [[ ! -z "$1" ]]; then
        MIX="$XIMIX_HOME/$1/conf/mixnet.xml"
	NODE="$XIMIX_HOME/$1/conf/node.xml"
fi

if [[ ! -f "$MIX" ]]; then
	echo "Network config not found for $1, path was $MIX";
	exit -1
fi

if [[ ! -f "$NODE" ]]; then
	echo "Node config was not found for $1, path was $NODE";
	exit -1;
fi

$JAVA_HOME/bin/java -cp "$XIMIX_HOME/libs/*" org.cryptoworkshop.ximix.node.Main $MIX $NODE "$@"
