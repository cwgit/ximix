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
package org.cryptoworkshop.ximix.common.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;


/**
 * A basic configuration object.
 */
public class Config
{
    private final File homeDirectory;

    private Element xmlNode;

    /**
     * Construct a config object from a XML file.
     *
     * @param configFile the name of the file.
     * @throws ConfigException if the file cannot be parsed.
     * @throws FileNotFoundException if the file cannot be found.
     */
    public Config(File configFile)
        throws ConfigException, FileNotFoundException
    {
        this.homeDirectory = configFile.getParentFile();

        try
        {
            init(new FileInputStream(configFile));
        }
        catch (FileNotFoundException fnf)
        {
            throw fnf;
        }
    }

    /**
     * Construct a config object from a XML stream.
     *
     * @throws ConfigException if the stream cannot be parsed.
     */
    public Config(InputStream stream)
        throws ConfigException
    {
        this.homeDirectory = null;

        init(stream);
    }

    /**
     * Construct a config object from a XML node.
     *
     * @throws ConfigException if the node cannot be parsed.
     */
    public Config(Node xmlNode)
        throws ConfigException
    {
        this.homeDirectory = null;

        this.xmlNode = (Element)xmlNode;
    }

    private void init(InputStream inputStream)
        throws ConfigException
    {
        try
        {
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = dbFactory.newDocumentBuilder();

            Document doc = docBuilder.parse(inputStream);

            xmlNode = doc.getDocumentElement();

        }
        catch (Exception e)
        {
            throw new ConfigException("error: " + e.getMessage(), e);
        }
    }

    /**
     * Return the location of the file defining this config, if there is one.
     *
     * @return location of home directory, null otherwise.
     */
    public File getHomeDirectory()
    {
        return homeDirectory;
    }

    /**
     * Return the value of an integer property.
     *
     * @param name the name of the property of interest.
     * @return the property's value.
     * @throws ConfigException if the config object cannot be parsed, or if the property cannot be found.
     */
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

    /**
     * Return the value of an integer property, returning def if the property is not set..
     *
     * @param name the name of the property of interest.
     * @param def the default value if the property is not set.
     * @return the property's value, or def if the property is not defined.
     * @throws ConfigException if the config object cannot be parsed.
     */
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

    /**
     * Return the value of a String property.
     *
     * @param name the name of the property of interest.
     * @return the property's value.
     * @throws ConfigException if the config object cannot be parsed, or if the property cannot be found.
     */
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

    /**
     * Return the value of a String property, returning def if the property is not set..
     *
     * @param name the name of the property of interest.
     * @param def the default value if the property is not set.
     * @return the property's value, or def if the property is not defined.
     * @throws ConfigException if the config object cannot be parsed.
     */
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

    public boolean hasConfig(String name)
    {
        String[] path = name.split("\\.");

        for (String elementName : path)
        {
            NodeList list = xmlNode.getElementsByTagName(elementName);
            if (list.getLength() != 0 && list.item(0).getNodeName().equals(path[path.length - 1]))
            {
                return true;
            }
        }

        return false;
    }


    public <T> T getConfigObject(String name, ConfigObjectFactory<T> factory)
        throws ConfigException
    {
        String[] path = name.split("\\.");

        for (String elementName : path)
        {
            NodeList list = xmlNode.getElementsByTagName(elementName);
            if (list.getLength() != 0 && list.item(0).getNodeName().equals(path[path.length - 1]))
            {
                return factory.createObject(list.item(0));
            }
        }

        throw new ConfigException("element " + name + " not found");
    }


    public <T> List<T> getConfigObjects(String name, ConfigObjectFactory<T> factory)
        throws ConfigException

    {
        List<T> configs = new ArrayList<T>();

        String[] path = name.split("\\.");

        for (String elementName : path)
        {
            NodeList list = xmlNode.getElementsByTagName(elementName);
            if (list.getLength() != 0 && list.item(0).getNodeName().equals(path[path.length - 1]))
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
