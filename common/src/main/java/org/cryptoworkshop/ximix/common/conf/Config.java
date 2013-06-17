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

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class Config {
    private Element xmlNode;

    public Config(File configFile)
            throws ConfigException {
        try {
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = dbFactory.newDocumentBuilder();

            Document doc = docBuilder.parse(configFile);

            xmlNode = doc.getDocumentElement();
        } catch (Exception e) {
            throw new ConfigException("error: " + e.getMessage(), e);
        }
    }

    public Config(Node xmlNode)
            throws ConfigException {
        this.xmlNode = (Element) xmlNode;
    }

    public int getIntegerProperty(String name)
            throws ConfigException {
        String[] path = name.split("\\.");

        for (String elementName : path) {
            NodeList list = xmlNode.getElementsByTagName(elementName);
            if (list.item(0).getNodeName().equals(path[path.length - 1])) {
                return Integer.parseInt(list.item(0).getTextContent());
            }
        }

        throw new ConfigException("property " + name + " not found");
    }


    public <T> List<T> getConfigObjects(String name, ConfigObjectFactory<T> factory)
            throws ConfigException {
        List<T> configs = new ArrayList<T>();

        String[] path = name.split("\\.");

        for (String elementName : path) {
            NodeList list = xmlNode.getElementsByTagName(elementName);
            if (list.item(0).getNodeName().equals(path[path.length - 1])) {
                for (int i = 0; i != list.getLength(); i++) {
                    configs.add(factory.createObject(list.item(i)));
                }

                return configs;
            }
        }

        throw new ConfigException("element " + name + " not found");
    }
}
