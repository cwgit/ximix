#!/bin/bash

if [[ -z "$XIMXI_CONSOLE_HOME" ]]; then
	L=`dirname $0`
	XIMIX_CONSOLE_HOME="$L/../"
fi

if [[ ! -d "$XIMIX_CONSOLE_HOME/libs" ]]; then
	echo "Could not find libs off XIMIX_CONSOLE_HOME ( $XIMIX_CONSOLE_HOME )"
	exit -1
fi

if [[ -z "$JAVA_HOME" ]]; then
     	echo "JAVA_HOME is not specified";  
fi

MIX="$XIMIX_CONSOLE_HOME/conf/mixnet.xml"
CONF="$XIMIX_CONSOLE_HOME/conf/console.xml"
PIDFILE="$XIMIX_CONSOLE_HOME/console.pid"

if [[ ! -f "$MIX" ]]; then
	echo "Network config not found, path was $MIX";
	exit -1
fi

if [[ ! -f "$CONF" ]]; then
	echo "Node config was not found, path was $CONF";
	exit -1;
fi

$JAVA_HOME/bin/java -cp "$XIMIX_CONSOLE_HOME/libs/*" org.cryptoworkshop.ximix.console.Main $CONF $MIX "$@" &
PID=$!

echo $PID > $PIDFILE
