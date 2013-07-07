package org.cryptoworkshop.ximix.test.node;

import org.cryptoworkshop.ximix.common.handlers.ThrowableHandler;

import java.util.ArrayList;
import java.util.List;

/**
 * Test throwable handler.
 */
public class SquelchingThrowableHandler implements ThrowableHandler
{
    private List<Class> squelchTypes = new ArrayList<Class>();

    @Override
    public void handle(Throwable throwable)
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
