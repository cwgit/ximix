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
package org.cryptoworkshop.ximix.client.connection;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Internal interpreter for the XML in the &lt;node&gt;&lt;/node&gt; block in the node configuration.
 */
class NodeConfig
{
    private InetAddress address;
    private int portNo;
    private String name;
    private Exception throwable;

    NodeConfig(Node configNode)
    {
        NodeList xmlNodes = configNode.getChildNodes();

        for (int i = 0; i != xmlNodes.getLength(); i++)
        {
            Node xmlNode = xmlNodes.item(i);

            if (xmlNode.getNodeName().equals("host"))
            {
                try
                {
                    address = InetAddress.getByName(xmlNode.getTextContent());
                }
                catch (UnknownHostException e)
                {
                    throwable = e;
                }
            }
            else if (xmlNode.getNodeName().equals("portNo"))
            {
                portNo = Integer.parseInt(xmlNode.getTextContent());
            }
            else if (xmlNode.getNodeName().equals("name"))
            {
                name = xmlNode.getTextContent().trim();
            }
        }
    }

    public Throwable getThrowable()
    {
        return throwable;
    }

    public InetAddress getAddress()
    {
        return address;
    }

    public int getPortNo()
    {
        return portNo;
    }

    public String getName()
    {
        return name;
    }
}

