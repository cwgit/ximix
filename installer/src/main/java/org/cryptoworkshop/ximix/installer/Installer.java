package org.cryptoworkshop.ximix.installer;

import org.w3c.dom.Node;

import java.io.File;
import java.net.URL;

/**
 *
 */
public class Installer {

    private File archive = null;
    private String configPath = null;
    private InstallerListener listener = null;

    /**
     * Create from a configuration.
     *
     * @param node The node.
     */
    public Installer(Node node) {
        try {
            URL u = Installer.class.getProtectionDomain().getCodeSource().getLocation();
            archive = new File(u.toURI());
        } catch (Exception ex) {
            listener.exception("Determining installer archive.",ex);
        }




    }


}
