package org.cryptoworkshop.ximix.installer;

import org.cryptoworkshop.ximix.installer.ui.AbstractInstallerUI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static org.cryptoworkshop.ximix.installer.InstallerConfig.Step;

/**
 *
 */
public class Installer
{

    private static HashMap<String, Object> properties = new HashMap<>();
    private File archive = null;
    private String configPath = null;
    private InstallerListener listener = null;
    private JarFile jarFile = null;


    /**
     *
     */
    public Installer(String jar)
    {
        try
        {

            if (jar != null)
            {
                archive = new File(jar);
            } else
            {
                URL u = Installer.class.getProtectionDomain().getCodeSource().getLocation();
                archive = new File(u.toURI());
            }
            AbstractInstallerUI ui = null;

            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = dbFactory.newDocumentBuilder();
            Document doc = docBuilder.parse(Installer.class.getResourceAsStream("/install.xml"));

            Element xmlNode = doc.getDocumentElement();

            InstallerConfig config = new InstallerConfig(xmlNode);


//            ui = new MainFrame();
//
//            //
//            // TODO uncomment for production, defaults to std in.
//            //
//
////            if (System.getProperty("os.name").indexOf("indows") > -1)
////            {
////                ui = new MainFrame();
////            } else
////            {
////                ui = new MainConsole();
////            }
//
//            ui.init(config);


            List<Object> operations = config.getInstallation().getOperations();

            jarFile = new JarFile(archive);

            properties.clear();
            properties.putAll(config.getInstallation().getProps());


            for (int t = 0; t < operations.size(); t++)
            {
                Object opp = operations.get(t);

                //
                // Steps define some sort of human interaction.
                //
                if (opp instanceof Step)
                {
                    switch (ui.show(((Step) opp).getStepInstance()))
                    {
                        case BACK:
                            if (t > 0)
                            {
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

                if (opp instanceof InstallerConfig.MovementCollection)
                {
                    for (InstallerConfig.Movement mv : ((InstallerConfig.MovementCollection) opp).getMovements())
                    {
                        movement(mv);
                    }
                } else if (opp instanceof InstallerConfig.Movement)
                {
                    movement((InstallerConfig.Movement) opp);
                }

            }


        } catch (Exception ex)
        {
            ex.printStackTrace();
        }
    }

    public static HashMap<String, Object> properties()
    {
        return properties;
    }

    public static void main(String[] args) throws Exception
    {
        if (args.length > 0)
        {
            new Installer(args[0]);
        } else
        {
            new Installer(null);
        }
    }

    public void movement(InstallerConfig.Movement movement)
    {
        ZipEntry ze = jarFile.getEntry(movement.getSrc());
        if (ze.isDirectory())
        {
            copyDir(ze, jarFile, ze.getName());

        } else
        {
            String dest = ze.getName();
            File out = new File((File) properties().get("installDir"), dest);
            try
            {
                copy(jarFile.getInputStream(ze), out, true);
            } catch (Exception e)
            {
                throw new RuntimeException(e);
            }

        }
    }

    public void copyDir(final ZipEntry entry, final ZipFile file, final String prefix)
    {
        Util.zipDir(entry.getName(), jarFile, new Util.ZipTraversal()
        {
            @Override
            public void entry(ZipEntry ze)
            {
                if (ze.getName().equals(entry.getName()))
                {
                    return;
                }

                if (ze.isDirectory())
                {
                    File out = new File((File) properties().get("installDir"), ze.getName());
                    out.mkdirs();
                    try
                    {
                        copyDir(ze, file, prefix);
                    } catch (Exception e)
                    {
                        e.printStackTrace();
                    }
                } else
                {

                    File out = new File((File) properties().get("installDir"), ze.getName());

                    try
                    {
                        copy(file.getInputStream(ze), out, true);
                    } catch (Exception e)
                    {
                        throw new RuntimeException(e);
                    }
                }
            }
        });
    }

    public void copy(InputStream is, File f, boolean close)
    {
        try
        {
            byte[] buf = new byte[4096];
            int l = 0;

            FileOutputStream fos = new FileOutputStream(f);

            while ((l = is.read(buf)) > -1)
            {
                fos.write(buf, 0, l);
            }

            fos.flush();
            fos.close();

            if (close)
            {
                is.close();
            }

        } catch (Exception ex)
        {
            throw new RuntimeException(ex);
        }
    }


}
