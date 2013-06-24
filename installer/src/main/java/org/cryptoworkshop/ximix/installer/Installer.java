package org.cryptoworkshop.ximix.installer;

import org.cryptoworkshop.ximix.installer.ui.AbstractInstallerUI;
import org.cryptoworkshop.ximix.installer.ui.MainConsole;
import org.cryptoworkshop.ximix.installer.ui.MainFrame;
import org.w3c.dom.Node;

import java.io.File;
import java.net.URL;

/**
 *
 */
public class Installer
{

    private File archive = null;
    private String configPath = null;
    private InstallerListener listener = null;

    /**
     * Create from a configuration.
     *
     * @param node The node.
     */
    public Installer(Node node)
    {
        try
        {
            URL u = Installer.class.getProtectionDomain().getCodeSource().getLocation();
            archive = new File(u.toURI());
        } catch (Exception ex)
        {
            listener.exception("Determining installer archive.", ex);
        }

//        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
//        DocumentBuilder docBuilder = dbFactory.newDocumentBuilder();

//        Document doc = docBuilder.parse(configFile);

//        xmlNode = doc.getDocumentElement();


    }

    public static void main(String[] args) throws Exception
    {
        AbstractInstallerUI ui = null;

        if (System.getProperty("os.name").indexOf("indows") > -1)
        {
            ui = new MainFrame();
        } else
        {
            ui = new MainConsole();
        }

        ui.init(null);
        ui.show();



    }


}
