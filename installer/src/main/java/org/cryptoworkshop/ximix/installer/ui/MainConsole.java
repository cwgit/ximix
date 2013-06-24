package org.cryptoworkshop.ximix.installer.ui;

import org.cryptoworkshop.ximix.installer.InstallerConfig;

import java.io.PrintWriter;

/**
 *
 */
public class MainConsole extends  AbstractInstallerUI
{
    private PrintWriter pw = null;

    public MainConsole()
    {
        pw = new PrintWriter(System.out);
    }

    @Override
    public void init(InstallerConfig config) throws Exception
    {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public void show() throws Exception
    {
        //To change body of implemented methods use File | Settings | File Templates.
    }
}
