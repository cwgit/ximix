package org.cryptoworkshop.ximix.console.config;

import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 *
 */
public class AdapterConfig extends HashMap<String, Object>
{
    private String className = null;
    private String id = null;
    private String name = null;
    private String description = null;

    public AdapterConfig(Node n)
    {
        NodeList nl = n.getChildNodes();
        for (int t = 0; t < nl.getLength(); t++)
        {
            Node node = nl.item(t);

            if ("class".equals(node.getNodeName()))
            {
                this.className = node.getTextContent();
            }

            if ("id".equals(node.getNodeName()))
            {
                this.id = node.getTextContent();
            }

            if ("name".equals(node.getNodeName()))
            {
                name = node.getTextContent();
            }

            if ("description".equals(node.getNodeName()))
            {
                description = node.getTextContent();
            }

            if ("property".equals(node.getNodeName()))
            {
                String name = node.getAttributes().getNamedItem("name").getTextContent();
                Object o = get(name);
                if (o == null)
                {
                    put(name, node.getTextContent());
                } else if (o instanceof List)
                {
                    ((List) o).add(node.getTextContent());
                } else if (o instanceof String)
                {
                    ArrayList l = new ArrayList();
                    l.add(remove(name));
                    l.add(node.getTextContent());
                }
            }
        }


    }

    public String getClassName()
    {
        return className;
    }

    public void setClassName(String className)
    {
        this.className = className;
    }

    public String getId()
    {
        return id;
    }

    public void setId(String id)
    {
        this.id = id;
    }

    public String getName()
    {
        return name;
    }

    public void setName(String name)
    {
        this.name = name;
    }

    public String getDescription()
    {
        return description;
    }

    public void setDescription(String description)
    {
        this.description = description;
    }
}
