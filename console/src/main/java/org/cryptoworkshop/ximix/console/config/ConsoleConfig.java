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
package org.cryptoworkshop.ximix.console.config;

import org.cryptoworkshop.ximix.common.util.EventNotifier;
import org.cryptoworkshop.ximix.common.util.JDKLoggingEventNotifier;

import java.util.ArrayList;
import java.util.List;

/**
 *
 */
public class ConsoleConfig
{
    private HTTPConfig httpConfig = null;
    private List<AdapterConfig> adapters = null;
    private EventNotifier eventNotifier = null;

    public ConsoleConfig()
    {

    }

    public HTTPConfig getHttpConfig()
    {
        return httpConfig;
    }

    public void setHttpConfig(HTTPConfig httpConfig)
    {
        this.httpConfig = httpConfig;
    }

    public List<AdapterConfig> getAdapters()
    {
        return adapters;
    }

    public void setAdapters(List<AdapterConfig> adapters)
    {
        this.adapters = adapters;
    }

    public void addAdapterConfig(AdapterConfig cfg)
    {
        if (adapters == null)
        {
            adapters = new ArrayList<>();
        }

        adapters.add(cfg);
    }

    public EventNotifier getEventNotifier()
    {
        return eventNotifier;
    }

    public void setEventNotifier(EventNotifier eventNotifier)
    {
        this.eventNotifier = eventNotifier;
    }
}
