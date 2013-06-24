package org.cryptoworkshop.ximix.installer.ui;

import org.cryptoworkshop.ximix.installer.InstallerConfig;

import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public abstract class AbstractInstallerUI
{
    private Map<String, Object> properties = new HashMap<String, Object>();

    public abstract void init(InstallerConfig config) throws Exception;

    public abstract void show() throws Exception;

    public Map<String, Object> getProperties()
    {
        return properties;
    }
}
