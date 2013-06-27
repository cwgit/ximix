package org.cryptoworkshop.ximix.installer.ui;

import org.cryptoworkshop.ximix.installer.InstallerConfig;
import org.cryptoworkshop.ximix.installer.ui.steps.AbstractInstallerStep;

import java.io.PrintWriter;
import java.util.concurrent.CountDownLatch;

/**
 *
 */
public class MainConsole extends AbstractInstallerUI
{
    private PrintWriter pw = null;


    public MainConsole()
    {
        pw = new PrintWriter(System.out);
    }

    @Override
    public void init(InstallerConfig config) throws Exception
    {

    }

    @Override
    public ShowResult show(AbstractInstallerStep step) throws Exception
    {

        return null;
    }
}
