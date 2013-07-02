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
package org.cryptoworkshop.ximix.common.conf;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;


public class Config
{
    private Element xmlNode;

    public Config(File configFile)
            throws ConfigException
    {
        try
        {
            init(new FileInputStream(configFile));
        } catch (Exception e)
        {
            throw new ConfigException("error: " + e.getMessage(), e);
        }

    }


    public Config(InputStream stream)
            throws ConfigException
    {
        init(stream);
    }


    public Config(Node xmlNode)
            throws ConfigException
    {
        this.xmlNode = (Element) xmlNode;
    }

    private void init(InputStream inputStream) throws ConfigException
    {
        try
        {
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = dbFactory.newDocumentBuilder();

            Document doc = docBuilder.parse(inputStream);

            xmlNode = doc.getDocumentElement();

        } catch (Exception e)
        {
            throw new ConfigException("error: " + e.getMessage(), e);
        }
    }

//    public static String getValueOf(NodeList nl, String name)
//    {
//        for (int t = 0; t < nl.getLength(); t++)
//        {
//            if (name.equals(nl.item(t).getNodeName()))
//            {
//                return nl.item(t).getTextContent();
//            }
//        }
//        return null;
//    }

//    public static Node getNodeOf(NodeList nl, String name) throws Exception
//    {
//        for (int t = 0; t < nl.getLength(); t++)
//        {
//            if (name.equals(nl.item(t).getNodeName()))
//            {
//                return nl.item(t);
//            }
//        }
//        throw new ConfigException("Node '"+name+"' was not found.");
//    }

    public int getIntegerProperty(String name)
            throws ConfigException
    {
        String[] path = name.split("\\.");

        for (String elementName : path)
        {
            NodeList list = xmlNode.getElementsByTagName(elementName);
            if (list.item(0).getNodeName().equals(path[path.length - 1]))
            {
                return Integer.parseInt(list.item(0).getTextContent());
            }
        }

        throw new ConfigException("property " + name + " not found");
    }

    public int getIntegerProperty(String name, int def)
            throws ConfigException
    {
        String[] path = name.split("\\.");

        for (String elementName : path)
        {
            NodeList list = xmlNode.getElementsByTagName(elementName);

            if (list == null)
            {
                throw new ConfigException("Path element '" + elementName + "' from '" + name + "' was not found.");
            }

            if (list.item(0).getNodeName().equals(path[path.length - 1]))
            {
                return Integer.parseInt(list.item(0).getTextContent());
            }
        }

        return def;
    }

    public String getStringProperty(String name)
            throws ConfigException
    {
        String[] path = name.split("\\.");

        for (String elementName : path)
        {
            NodeList list = xmlNode.getElementsByTagName(elementName);
            if (list.item(0).getNodeName().equals(path[path.length - 1]))
            {
                return list.item(0).getTextContent();
            }
        }

        throw new ConfigException("property " + name + " not found");
    }

    public String getStringProperty(String name, String def)
            throws ConfigException
    {
        String[] path = name.split("\\.");

        for (String elementName : path)
        {
            NodeList list = xmlNode.getElementsByTagName(elementName);

            if (list.item(0) == null)
            {
                throw new ConfigException("Path element '" + elementName + "' from '" + name + "' was not found.");
            }

            if (list.item(0).getNodeName().equals(path[path.length - 1]))
            {
                return list.item(0).getTextContent();
            }
        }

        return def;
    }

//    public NodeList getNodeList(String name) throws ConfigException
//    {
//        String[] path = name.split("\\.");
//
//        for (String elementName : path)
//        {
//            NodeList list = xmlNode.getElementsByTagName(elementName);
//            if (list.item(0).getNodeName().equals(path[path.length - 1]))
//            {
//                return list.item(0).getChildNodes();
//            }
//        }
//        throw new ConfigException("property " + name + " not found");
//    }

    public <T> List<T> getConfigObjects(String name, ConfigObjectFactory<T> factory)
            throws ConfigException

    {
        List<T> configs = new ArrayList<T>();

        String[] path = name.split("\\.");

        for (String elementName : path)
        {
            NodeList list = xmlNode.getElementsByTagName(elementName);
            if (list.item(0).getNodeName().equals(path[path.length - 1]))
            {
                for (int i = 0; i != list.getLength(); i++)
                {
                    configs.add(factory.createObject(list.item(i)));
                }

                return configs;
            }
        }

        throw new ConfigException("element " + name + " not found");
    }
}
