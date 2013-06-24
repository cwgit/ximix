import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class Extractor
{
    private static final String DEFAULT_DIR = "/opt/ximix/node";

    private static boolean headless = true;



    private static URL getJarFileName()
    {
        return Extractor.class.getProtectionDomain().getCodeSource().getLocation();
    }

    private static String readLine(String defValue)
        throws IOException
    {
        int ch;
        StringBuilder bldr = new StringBuilder();

        while ((ch = System.in.read()) != '\r' && ch != '\n')
        {
            bldr.append((char)ch);
        }

        String out = bldr.toString().trim();

        if (out.length() == 0)
        {
            return defValue;
        }

        return out;
    }

    public static void main(String[] args)
        throws IOException, URISyntaxException
    {
        if (args.length != 2)
        {
            System.err.println("Please provide configuration files.");
            System.exit(1);
        }

        JarFile jar = new JarFile(new File(getJarFileName().toURI()));

        String outDir = DEFAULT_DIR;

        System.err.print("Please enter the installation directory [" + outDir + "]");

        outDir = readLine(outDir);

        System.err.println(outDir);

        for (Enumeration en = jar.entries(); en.hasMoreElements();)
        {
            JarEntry entry = (JarEntry)en.nextElement();

            System.out.println(entry.getName());
        }
    }
}
