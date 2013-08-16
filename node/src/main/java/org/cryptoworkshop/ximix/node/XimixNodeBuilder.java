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
import java.util.Map;
import java.util.logging.Logger;

import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.config.ConfigException;
import org.cryptoworkshop.ximix.common.handlers.EventNotifier;
import org.cryptoworkshop.ximix.common.service.ServicesConnection;
import org.cryptoworkshop.ximix.registrar.XimixRegistrarFactory;

public class XimixNodeBuilder
{
    static EventNotifier eventNotifier = new EventNotifier()
    {
        Logger L = Logger.getLogger("ximix");

        @Override
        public void notify(EventNotifier.Level level, Throwable throwable)
        {
            notify(level, null, throwable);
        }

        @Override
        public void notify(EventNotifier.Level level, Object detail)
        {
            notify(level, detail, null);
        }

        @Override
        public void notify(EventNotifier.Level level, Object detail, Throwable throwable)
        {
            java.util.logging.Level level1 = null;
            switch (level)
            {
                case DEBUG:
                    level1 = java.util.logging.Level.FINE;
                    break;
                case INFO:
                    level1 = java.util.logging.Level.INFO;
                    break;
                case WARN:
                    level1 = java.util.logging.Level.WARNING;
                    break;
                case ERROR:
                    level1 = java.util.logging.Level.SEVERE;
                    break;
            }

            L.log(level1, detail.toString(), throwable);
        }
    };

    private final Config peersConfig;


    public XimixNodeBuilder(Config peersConfig)
    {
        this.peersConfig = peersConfig;
    }

    public XimixNodeBuilder(File file)
        throws ConfigException, FileNotFoundException
    {
        this(new Config(file));
    }

    public XimixNodeBuilder withThrowableListener(EventNotifier eventNotifier)
    {
        this.eventNotifier = eventNotifier;

        return this;
    }

    public XimixNode build(Config nodeConfig)
        throws ConfigException
    {
        final Map<String, ServicesConnection> servicesMap = XimixRegistrarFactory.createServicesRegistrarMap(peersConfig);

        return new DefaultXimixNode(nodeConfig, servicesMap, eventNotifier);
    }

    public XimixNode build(File file)
        throws ConfigException, FileNotFoundException
    {
        return build(new Config(file));
    }
}
