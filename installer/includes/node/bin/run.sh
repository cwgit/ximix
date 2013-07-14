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


$JAVA_HOME/bin/java -cp "$XIMIX_HOME/libs/*" org.cryptoworkshop.ximix.node.Main "$@"
