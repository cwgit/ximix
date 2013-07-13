#!/bin/bash

if [[ -z "$XIMXI_NODE_ROOT" ]]; then
	L=`dirname $0`
	XIMIX_NODE_ROOT="$L/../"
	 
fi

if [[ ! -f "$XIMIX_NODE_ROOT/libs/node.jar" ]]; then
	echo "Could not find libs/node.jar off XIMIX_NODE_ROOT ($XIMIX_NODE_ROOT)"
	exit -1
fi


if [[ -z "$JAVA_HOME" ]]; then
     	echo "JAVA_HOME is not specified";  
fi


$JAVA_HOME/bin/java -cp "$XIMIX_NODE_ROOT/libs/*" org.cryptoworkshop.ximix.node.Main "$@"
