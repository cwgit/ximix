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
package org.cryptoworkshop.ximix.node;

import java.io.File;
import java.io.FileNotFoundException;

import org.cryptoworkshop.ximix.common.config.ConfigException;

public class Main
{
    public static void main(String[] args)
    {

        if (args.length < 2)
        {
            System.out.println("\r\nXimix Node executable jar.\r\n");
            System.out.println("Usage: <mixnet config> <node config>");
            System.out.println("Example: java -jar XimixNode.jar mixnet.xml node.xml\r\n");
            System.exit(0);
        }

        try
        {

            XimixNodeBuilder builder = new XimixNodeBuilder(new File(args[0]));

            XimixNode node = builder.build(new File(args[1]));

            node.start();
        }
        catch (ConfigException e)
        {
            e.printStackTrace();
        }
        catch (FileNotFoundException e)
        {
            e.printStackTrace();
        }

    }

}
