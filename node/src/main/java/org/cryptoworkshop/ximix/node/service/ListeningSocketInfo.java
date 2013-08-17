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
package org.cryptoworkshop.ximix.node.service;

/**
*
*/
public class ListeningSocketInfo
{
    private final int port;
    private final int backlog;
    private final String bindAddress;
    private final String name;

    public ListeningSocketInfo(String nodeName, int port, int backlog, String bindAddress)
    {
        this.port = port;
        this.backlog = backlog;
        this.bindAddress = bindAddress;
        this.name = nodeName;
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

        if (port != that.port)
        {
            return false;
        }
        if (!name.equals(that.name))
        {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode()
    {
        int result = port;
        result = 31 * result + name.hashCode();
        return result;
    }
}
