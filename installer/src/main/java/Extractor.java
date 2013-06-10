import java.io.IOException;
import java.net.URL;
import java.util.Enumeration;
import java.util.jar.JarFile;

public class Extractor
{
    private static String getJarFileName()
    {
        URL urlJar = Extractor.class.getClassLoader().getSystemResource("java.class");
        String urlStr = urlJar.toString();
        int from = "jar:file:".length();
        int to = urlStr.indexOf("!/");
        return urlStr.substring(from, to);
    }

    public static void main(String[] args)
        throws IOException
    {
        if (args.length != 2)
        {
            System.err.println("Please provide an installation directory.");
            System.exit(1);
        }

        JarFile jar = new JarFile(getJarFileName());

        for (Enumeration en = jar.entries(); en.hasMoreElements();)
        {

        }
    }
}
