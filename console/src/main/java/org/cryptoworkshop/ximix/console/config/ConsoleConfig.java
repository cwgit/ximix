package org.cryptoworkshop.ximix.console.config;

import java.util.ArrayList;
import java.util.List;

/**
 *
 */
public class ConsoleConfig
{
    private HTTPConfig httpConfig = null;
    private List<AdapterConfig> adapters = null;

    public ConsoleConfig() {

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

}
