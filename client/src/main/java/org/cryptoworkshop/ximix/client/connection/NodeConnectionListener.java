package org.cryptoworkshop.ximix.client.connection;

public interface NodeConnectionListener
{
    void status(String name, boolean isAvailable);
}
