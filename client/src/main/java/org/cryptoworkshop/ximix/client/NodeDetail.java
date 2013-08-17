package org.cryptoworkshop.ximix.client;

import java.net.InetAddress;

public class NodeDetail
{
    private final InetAddress address;
    private final int portNo;
    private final String name;

    public NodeDetail(String name, InetAddress address, int portNo)
    {
        this.address = address;
        this.portNo = portNo;
        this.name = name;
    }

    public int getPortNo()
    {
        return portNo;
    }

    public String getName()
    {
        return name;
    }

    public InetAddress getAddress()
    {
        return address;
    }
}
