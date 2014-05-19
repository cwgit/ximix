#!/bin/bash

if [[ -z "$XIMIX_HOME" ]]; then
	L=`dirname $0`
	XIMIX_HOME="$L/../"
fi

	 
if [[ -z "$XIMIX_JAVA_OPTS" ]]; then
    XIMIX_JAVA_OPTS=-Xmx768m
fi

if [[ "x$1" = "x" ]]; then
        echo "Parameter 1 must be node name, eg start.sh node1"
        exit -1
fi

if [[ ! -d "$XIMIX_HOME/libs" ]]; then
	echo "Could not find libs directory off XIMIX_HOME ( $XIMIX_HOME )"
	exit -1
fi


if [[ -z "$JAVA_HOME" ]]; then
     	echo "JAVA_HOME is not specified";  
fi


if [[ ! -z "$1" ]]; then
        MIX="$XIMIX_HOME/$1/conf/mixnet.xml"
	NODE="$XIMIX_HOME/$1/conf/node.xml"
	PIDFILE="$XIMIX_HOME/$1/$1.pid"
fi

if [[ ! -f "$MIX" ]]; then
	echo "Network config not found for $1, path was $MIX";
	exit -1
fi

if [[ ! -f "$NODE" ]]; then
	echo "Node config was not found for $1, path was $NODE";
	exit -1;
fi

$JAVA_HOME/bin/java $XIMIX_JAVA_OPTS -cp "$XIMIX_HOME/libs/*" org.cryptoworkshop.ximix.node.Main $MIX $NODE "$@" &
PID=$!

echo $PID > $PIDFILE
