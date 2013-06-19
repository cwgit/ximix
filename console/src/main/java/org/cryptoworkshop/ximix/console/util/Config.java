package org.cryptoworkshop.ximix.console.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.Reader;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLConnection;
import java.util.Enumeration;
import java.util.Properties;

/**
 * Config loader and singleton.
 */
public class Config {


    private static Config config = null;
    private static boolean loaded = false;
    private Properties properties = new Properties();

    private Config() {

    }

    private Config(Object source) throws Exception {
        if (source instanceof Properties) {
            Enumeration e = ((Properties) source).propertyNames();
            while (e.hasMoreElements()) {
                Object o = e.nextElement();
                properties.put(o, ((Properties) source).getProperty(o.toString()));
            }
        } else if (source instanceof File) {
            properties.load(new FileInputStream((File) source));
        } else if (source instanceof InputStream) {
            properties.load((InputStream) source);
        } else if (source instanceof Reader) {
            properties.load((Reader) source);
        } else if (source instanceof URL) {
            URLConnection con = ((URL) source).openConnection();
            InputStream in = con.getInputStream();
            properties.load(in);
            try {
                in.close();
            } catch (Exception ex) {
                // Try and close it if it has not been closed by the other end.
            }
        } else {
            throw new IllegalArgumentException("Config accepts, InputStream, File, Reader or a properties object");
        }
    }

    public static Config config() {
        if (config == null) {
            throw new IllegalStateException("Call Config.load(<source>) to load config");
        }
        return config;
    }

    public static Config getAdapterSubset(String prefix) {
        Config cfg = new Config();

        cfg.properties = new Properties();

        Enumeration e = config.properties.propertyNames();
        while (e.hasMoreElements()) {
            String o = e.nextElement().toString();
            if (o.startsWith(prefix)) {
                cfg.properties.put(o.substring(o.indexOf('.', prefix.length()) + 1), config.properties.getProperty(o.toString()));
            }
        }

        return cfg;
    }

    public static Config load(Object source) throws Exception {
        config = new Config(source);
        loaded = true;
        return config;
    }

    public static boolean isLoaded() {
        return loaded;
    }

    public String getProperty(String name, String def) {
        return properties.getProperty(name, def);
    }

    public String getProperty(String name) {
        return properties.getProperty(name);
    }

    public Integer getProperty(String name, Integer def) {
        if (properties.containsKey(name)) {
            return Integer.valueOf(properties.getProperty(name));
        }
        return def;
    }

    public Long getProperty(String name, Long def) {
        if (properties.containsKey(name)) {
            return Long.valueOf(properties.getProperty(name));
        }
        return def;
    }

    public InetAddress getInetAddress(String name, InetAddress def) throws Exception {
        if (properties.containsKey(name)) {
            return InetAddress.getByName(properties.getProperty(name));
        }
        return def;
    }


}
