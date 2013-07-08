package org.cryptoworkshop.ximix.test.node;

import org.cryptoworkshop.ximix.common.handlers.ThrowableListener;

import java.util.ArrayList;
import java.util.List;

/**
 * Test throwable handler.
 */
public class SquelchingThrowableHandler implements ThrowableListener
{
    private List<Class> squelchTypes = new ArrayList<Class>();
    private boolean printOnly = false;

    @Override
    public void notify(Throwable throwable)
    {
        if (squelchTypes.contains(throwable.getClass()))
        {
            return;
        }
        if (printOnly)
        {
            throwable.printStackTrace();
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
