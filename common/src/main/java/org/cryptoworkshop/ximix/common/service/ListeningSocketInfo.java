package org.cryptoworkshop.ximix.common.service;

/**
*
*/
public class ListeningSocketInfo
{
    private final int port;
    private final int backlog;
    private final String bindAddress;

    public ListeningSocketInfo(int port, int backlog, String bindAddress)
    {
        this.port = port;
        this.backlog = backlog;
        this.bindAddress = bindAddress;
    }

    public int getPort()
    {
        return port;
    }

    public int getBacklog()
    {
        return backlog;
    }

    public String getBindAddress()
    {
        return bindAddress;
    }

    @Override
    public String toString()
    {
        return "ListeningSocketInfo{" +
            "port=" + port +
            ", backlog=" + backlog +
            ", bindAddress='" + bindAddress + '\'' +
            '}';
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }

        ListeningSocketInfo that = (ListeningSocketInfo)o;

        if (backlog != that.backlog)
        {
            return false;
        }
        if (port != that.port)
        {
            return false;
        }
        if (bindAddress != null ? !bindAddress.equals(that.bindAddress) : that.bindAddress != null)
        {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode()
    {
        int result = port;
        result = 31 * result + backlog;
        result = 31 * result + (bindAddress != null ? bindAddress.hashCode() : 0);
        return result;
    }
}
