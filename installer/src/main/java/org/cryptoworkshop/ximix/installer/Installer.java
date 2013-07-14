package org.cryptoworkshop.ximix.installer;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.swing.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.Console;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HashMap;
import java.util.List;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 *
 */
public class Installer
{

    public static final String INSTALL_DIR = "installDir";
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
            }
            else
            {
                URL u = Installer.class.getProtectionDomain().getCodeSource().getLocation();
                archive = new File(u.toURI());
            }

            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = dbFactory.newDocumentBuilder();
            Document doc = docBuilder.parse(Installer.class.getResourceAsStream("/install.xml"));

            Element xmlNode = doc.getDocumentElement();

            InstallerConfig config = new InstallerConfig(xmlNode);


            Console console = System.console();
            if (console == null)
            {
                JOptionPane.showMessageDialog(null, "Please run from command line.", "Problem.", JOptionPane.WARNING_MESSAGE);
                System.exit(0);
            }


            List<Object> operations = config.getInstallation().getOperations();

            jarFile = new JarFile(archive);

            properties.clear();
            properties.putAll(config.getInstallation().getProps());


            for (int t = 0; t < operations.size(); t++)
            {
                Object opp = operations.get(t);


                if (opp instanceof InstallerConfig.Step)
                {
                    String n = ((InstallerConfig.Step)opp).getName();
                    if ("askInstallLocation".equals(n))
                    {
                        askInstallDir(console);
                    }
                }
                else if (opp instanceof InstallerConfig.MovementCollection)
                {
                    for (InstallerConfig.Movement mv : ((InstallerConfig.MovementCollection)opp).getMovements())
                    {
                        movement(mv);
                    }
                }
                else if (opp instanceof InstallerConfig.Movement)
                {
                    movement((InstallerConfig.Movement)opp);
                }
                else if (opp instanceof InstallerConfig.PosixPerms)
                {

                    try
                    {
                        File f = new File((File)properties().get(INSTALL_DIR), ((InstallerConfig.PosixPerms)opp).getRelPath());
                        if (!f.exists())
                        {
                            System.err.println("Unable to find file " + f);
                        }

                        Path p = Paths.get(f.toURI());

                        // TODO consider the security implications where the relative path has elements like "../" etc.

                        java.nio.file.Files.setPosixFilePermissions(p, PosixFilePermissions.fromString(((InstallerConfig.PosixPerms)opp).getPermissions()));
                    }
                    catch (UnsupportedOperationException uoe)
                    {
                        // Ignore..
                    }
                }

            }


        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
    }

    public static HashMap<String, Object> properties()
    {
        return properties;
    }

    public static void main(String[] args)
        throws Exception
    {
        if (args.length > 0)
        {
            new Installer(args[0]);
        }
        else
        {
            new Installer(null);
        }
    }

    private void askInstallDir(Console console)
        throws Exception
    {
        File dir = (File)properties().get(INSTALL_DIR);

        for (; ; )
        {
            String i = console.readLine("Enter Install Directory [%s] >", dir.getCanonicalPath());
            if (!i.isEmpty())
            {
                dir = new File(i);
            }

            i = console.readLine("Condfirm Install to '%s' Yes or [No] >", dir.getCanonicalPath());
            if (i.toLowerCase().startsWith("y"))
            {
                properties().put(INSTALL_DIR, dir);
                break;
            }

        }
    }

    public void movement(InstallerConfig.Movement movement)
    {
        ZipEntry ze = jarFile.getEntry(movement.getSrc());
        if (ze.isDirectory())
        {
            copyDir(ze, jarFile, ze.getName());

        }
        else
        {
            String dest = ze.getName();
            File out = new File((File)properties().get(INSTALL_DIR), dest);
            try
            {
                copy(jarFile.getInputStream(ze), out, true);
            }
            catch (Exception e)
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
                    File out = new File((File)properties().get(INSTALL_DIR), ze.getName());
                    out.mkdirs();
                    try
                    {
                        copyDir(ze, file, prefix);
                    }
                    catch (Exception e)
                    {
                        e.printStackTrace();
                    }
                }
                else
                {

                    File out = new File((File)properties().get(INSTALL_DIR), ze.getName());

                    try
                    {
                        copy(file.getInputStream(ze), out, true);
                    }
                    catch (Exception e)
                    {
                        throw new RuntimeException(e);
                    }
                }
            }
        });
    }

    public void copy(InputStream is, File f, boolean close)
    {

        System.out.println("Unpacking: " + f);

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

        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex);
        }
    }


}
