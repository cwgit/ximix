package org.cryptoworkshop.ximix.common.util;

import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.logging.Logger;

/**
 * Default logging event notifier that prints via Java Util Logging.
 */
public class JDKLoggingEventNotifier
    implements EventNotifier
{
    private final String name;
    private final Logger l;

    /**
     * Build from xml configuration.
     *
     * @param parent
     */
    public JDKLoggingEventNotifier(Node parent)
    {
        String _name = "ximix";
        NodeList nl = parent.getChildNodes();
        for (int t = 0; t < nl.getLength(); t++)
        {
            Node node = nl.item(t);

            if ("name".equals(node.getNodeName()))
            {
                _name = node.getTextContent();
            }
        }

        name = _name;
        l = Logger.getLogger(name);

    }

    /**
     * Default, logs to "ximix"
     */
    public JDKLoggingEventNotifier()
    {
        name = "ximix";
        l = Logger.getLogger(name);
    }

    /**
     * Create defining the name.
     *
     * @param name The name to log to.
     */
    public JDKLoggingEventNotifier(String name)
    {
        this.name = name;
        l = Logger.getLogger(this.name);
    }

    @Override
    public void notify(EventNotifier.Level level, Throwable throwable)
    {
        notify(level, null, throwable);
    }

    @Override
    public void notify(EventNotifier.Level level, Object detail)
    {
        notify(level, detail, null);
    }

    @Override
    public void notify(EventNotifier.Level level, Object detail, Throwable throwable)
    {
        java.util.logging.Level level1 = null;
        switch (level)
        {
            case DEBUG:
                level1 = java.util.logging.Level.FINE;
                break;
            case INFO:
                level1 = java.util.logging.Level.INFO;
                break;
            case WARN:
                level1 = java.util.logging.Level.WARNING;
                break;
            case ERROR:
                level1 = java.util.logging.Level.SEVERE;
                break;
        }

        l.log(level1, detail.toString(), throwable);
    }
}
