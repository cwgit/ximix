package org.cryptoworkshop.ximix.test.node;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.config.ConfigException;

/**
 *
 */
public class ResourceAnchor
{
    public static Config load(String path)
        throws ConfigException
    {
        return new Config(ResourceAnchor.class.getResourceAsStream(path));
    }

    public static Config load(File homeDirectory, String path)
        throws ConfigException, IOException
    {
        createFile(ResourceAnchor.class.getResourceAsStream("/conf/" + path.substring(path.lastIndexOf('/') + 1, path.lastIndexOf('.')) + "CaStore.p12"), homeDirectory, "nodeCaStore.p12");
        createFile(ResourceAnchor.class.getResourceAsStream("/conf/trustCa.pem"), homeDirectory, "trustCa.pem");

        InputStream cIn = ResourceAnchor.class.getResourceAsStream(path);

        File confFile = createFile(cIn, homeDirectory, path.substring(path.lastIndexOf('/') + 1));

        return new Config(confFile);
    }

    private static File createFile(InputStream in, File homeDirectory, String name)
        throws IOException
    {
        File confFile = new File(homeDirectory, name);
        FileOutputStream fOut = new FileOutputStream(confFile);

        int ch;
        while ((ch = in.read()) >= 0)
        {
            fOut.write(ch);
        }

        fOut.close();
        return confFile;
    }
}
