package org.cryptoworkshop.ximix.test.node;

import java.util.ArrayList;
import java.util.List;

import org.cryptoworkshop.ximix.common.handlers.ThrowableListener;

/**
 * Test throwable handler.
 */
public class SquelchingThrowableHandler implements ThrowableListener
{
    private List<Class> squelchTypes = new ArrayList<Class>();

    @Override
    public void notify(Throwable throwable)
    {
        if (squelchTypes.contains(throwable.getClass()))
        {
            return;
        }

        throw new RuntimeException(throwable);
    }

    public SquelchingThrowableHandler squelchType(Class type)
    {
        squelchTypes.add(type);
        return this;
    }
}
