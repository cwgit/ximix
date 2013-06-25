package org.cryptoworkshop.ximix.installer.ui.steps;

import java.io.File;

/**
 *     The location to install the nodes.
 */
public class SelectInstallLocation extends AbstractInstallerStep
{

    File installLocation = new File("./ximix/");

    public static final String ID = "install_location";


    public SelectInstallLocation()
    {
        super();
        inputType = InputType.FILE;
    }


    @Override
    public String acceptValue(Object value)
    {
        installLocation = (File)value;
        return null;
    }

    @Override
    public Object getDefault()
    {
        return installLocation;
    }
}
