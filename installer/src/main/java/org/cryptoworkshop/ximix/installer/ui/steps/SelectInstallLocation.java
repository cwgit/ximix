package org.cryptoworkshop.ximix.installer.ui.steps;

import java.io.File;
import java.util.HashMap;

/**
 *     The location to install the nodes.
 */
public class SelectInstallLocation extends AbstractInstallerStep
{

    File installLocation = new File("./ximix/");

    public static final String ID = "installDir";




    public SelectInstallLocation()
    {
        super();

        FileInputConstraints constraints = new FileInputConstraints();
        constraints.setOnlyDirectories(true);
        userInputs.add(new UserInput("Location:",InputType.FILE,ID).setToolTip("Installation directory").setConstraints(constraints));
        title = "Installation location.";
        content="Select the path to the directory on your file system Ximix will be installed.";
    }


    @Override
    public String acceptValue(HashMap<String,Object> value)
    {
        installLocation = (File)value.get(ID);
        return null;
    }

    @Override
    public Object getDefault()
    {
        return installLocation;
    }
}
