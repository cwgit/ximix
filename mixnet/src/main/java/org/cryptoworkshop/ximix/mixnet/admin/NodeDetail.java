package org.cryptoworkshop.ximix.mixnet.admin;

/**
 * By way of example.
 */
public class NodeDetail {
    private int port = 0;
    private String name = null;
    private long startTimestamp = System.currentTimeMillis();

    private int hash = 0;

    public NodeDetail() {
        hash = hashCode();
    }

    public NodeDetail(int port, String name) {
        this.port = port;
        this.name = name;
        hash = hashCode();
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
        hash = hashCode();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
        hash = hashCode();
    }

    public long getStartTimestamp() {
        return startTimestamp;
    }

    public void setStartTimestamp(long startTimestamp) {
        this.startTimestamp = startTimestamp;
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

        NodeDetail that = (NodeDetail) o;

        if (port != that.port) return false;
        if (name != null ? !name.equals(that.name) : that.name != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = port;
        result = 31 * result + (name != null ? name.hashCode() : 0);
        return result;
    }
}
