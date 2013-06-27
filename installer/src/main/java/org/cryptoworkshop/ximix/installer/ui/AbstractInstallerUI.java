package org.cryptoworkshop.ximix.installer.ui;

import org.cryptoworkshop.ximix.installer.InstallerConfig;
import org.cryptoworkshop.ximix.installer.ui.steps.AbstractInstallerStep;

import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public abstract class AbstractInstallerUI
{
    private Map<String, Object> properties = new HashMap<String, Object>();

    public abstract void init(InstallerConfig config) throws Exception;

    public Map<String, Object> getProperties()
    {
        return properties;
    }

    public abstract ShowResult show(AbstractInstallerStep step) throws Exception;

    public enum ShowResult
    {
        BACK, NEXT, CANCEL, EXIT
    }




}
