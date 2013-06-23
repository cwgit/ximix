package org.cryptoworkshop.ximix.console.config;

import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 *
 */
public class HTTPConfig
{
    private int port = 1887;
    private String host = "localhost";

    public HTTPConfig(Node n)
    {
        NodeList nl = n.getChildNodes();
        for (int t = 0; t < nl.getLength(); t++)
        {
            Node node = nl.item(t);
            if ("bind-port".equals(node.getNodeName()))
            {
                this.port = Integer.valueOf(node.getTextContent().trim());
            }

            if ("bind-host".equals(node.getNodeName()))
            {
                host = node.getTextContent();
            }
        }
    }

    public int getPort()
    {
        return port;
    }

    public void setPort(int port)
    {
        this.port = port;
    }

    public String getHost()
    {
        return host;
    }

    public void setHost(String host)
    {
        this.host = host;
    }
}
