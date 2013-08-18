/**
 * Copyright 2013 Crypto Workshop Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.cryptoworkshop.ximix.client;

import java.net.InetAddress;

/**
 * Carrier class for basic node details.
 */
public class NodeDetail
{
    private final InetAddress address;
    private final int portNo;
    private final String name;

    /**
     * Base constructor.
     *
     * @param name the name of the node.
     * @param address the address of the node.
     * @param portNo the port number the node is listening on.
     */
    public NodeDetail(String name, InetAddress address, int portNo)
    {
        this.address = address;
        this.portNo = portNo;
        this.name = name;
    }

    /**
     * Return the port number the node is listening on.
     *
     * @return node's port number.
     */
    public int getPortNo()
    {
        return portNo;
    }

    /**
     * Return the name of the node.
     *
     * @return the node's name.
     */
    public String getName()
    {
        return name;
    }

    /**
     * Return the address of the node.
     *
     * @return the node's address.
     */
    public InetAddress getAddress()
    {
        return address;
    }
}
