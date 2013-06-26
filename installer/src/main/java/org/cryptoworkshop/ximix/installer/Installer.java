package org.cryptoworkshop.ximix.installer;

import org.cryptoworkshop.ximix.installer.ui.AbstractInstallerUI;
import org.cryptoworkshop.ximix.installer.ui.MainFrame;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.net.URL;
import java.util.HashMap;
import java.util.List;

import static org.cryptoworkshop.ximix.installer.InstallerConfig.Step;

/**
 *
 */
public class Installer {

    private static HashMap<String, Object> properties = new HashMap<>();
    private File archive = null;
    private String configPath = null;
    private InstallerListener listener = null;


    /**
     *
     */
    public Installer() {
        try {
            URL u = Installer.class.getProtectionDomain().getCodeSource().getLocation();
            archive = new File(u.toURI());

            AbstractInstallerUI ui = null;

            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = dbFactory.newDocumentBuilder();
            Document doc = docBuilder.parse(Installer.class.getResourceAsStream("/install.xml"));

            Element xmlNode = doc.getDocumentElement();

            InstallerConfig config = new InstallerConfig(xmlNode);


            ui = new MainFrame();

            //
            // TODO uncomment for production, defaults to std in.
            //

//            if (System.getProperty("os.name").indexOf("indows") > -1)
//            {
//                ui = new MainFrame();
//            } else
//            {
//                ui = new MainConsole();
//            }

            ui.init(config);


            List<Object> operations = config.getInstallation().getOperations();

            for (int t = 0; t < operations.size(); t++) {
                Object opp = operations.get(t);
                if (opp instanceof Step) {
                    switch (ui.show(((Step) opp).getStepInstance())) {
                        case BACK:
                            if (t > 0) {
                                t -= 2;
                            }
                            break;
                        case NEXT:
                            continue;

                        case CANCEL:
                            System.exit(0);
                            break;
                    }


                    continue;
                }

            }


        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static HashMap<String, Object> properties() {
        return properties;
    }

    public static void main(String[] args) throws Exception {
        new Installer();
    }

}
