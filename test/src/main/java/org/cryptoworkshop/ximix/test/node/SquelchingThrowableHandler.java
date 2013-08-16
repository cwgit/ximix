package org.cryptoworkshop.ximix.test.node;

import org.cryptoworkshop.ximix.common.handlers.EventNotifier;

import java.util.ArrayList;
import java.util.List;

/**
 * Test throwable handler.
 */
public class SquelchingThrowableHandler implements EventNotifier
{
    private List<Class> squelchTypes = new ArrayList<Class>();
    private boolean printOnly = false;

    @Override
    public void notify(Level level, Throwable throwable)
    {
        notify(level,null, throwable);
    }

    @Override
    public void notify(Level level, Object detail)
    {
        System.err.println(level+" "+detail);
    }

    @Override
    public void notify(Level level, Object detail, Throwable throwable)
    {
        if (squelchTypes.contains(throwable.getClass()))
        {
            System.out.println("SQUELCH: "+throwable.getMessage());
            return;
        }
        if (printOnly)
        {
            System.err.println(level+" "+detail);
            throwable.printStackTrace(System.err);
        }
        else
        {
            throw new RuntimeException(throwable);
        }
    }

    public SquelchingThrowableHandler squelchType(Class type)
    {
        squelchTypes.add(type);
        return this;
    }

    public List<Class> getSquelchTypes()
    {
        return squelchTypes;
    }

    public void setSquelchTypes(List<Class> squelchTypes)
    {
        this.squelchTypes = squelchTypes;
    }

    public boolean isPrintOnly()
    {
        return printOnly;
    }

    public void setPrintOnly(boolean printOnly)
    {
        this.printOnly = printOnly;
    }
}
