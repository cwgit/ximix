package org.cryptoworkshop.ximix.common.console.model;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * A class that will hold details of a node from the UI perspective.
 */

public class NodeInfo {
    private String name = "Undefined";
    private long started = System.currentTimeMillis();
    private String hostName = null;
    private int hash = 0;


    public NodeInfo() {

        try {
            hostName = InetAddress.getLocalHost().toString();
        } catch (UnknownHostException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
    }

    public NodeInfo(String name) {
        this.name = name;
        try {
            hostName = InetAddress.getLocalHost().toString();
        } catch (UnknownHostException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public long getStarted() {
        return started;
    }

    public void setStarted(long started) {
        this.started = started;
    }

    public String getHostName() {
        return hostName;
    }

    public void setHostName(String hostName) {
        this.hostName = hostName;
    }

    public int getHash() {
        return hash;
    }

    public void setHash(int hash) {
        this.hash = hash;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        NodeInfo nodeInfo = (NodeInfo) o;

        if (!name.equals(nodeInfo.name)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }
}
