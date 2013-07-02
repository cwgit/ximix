package org.cryptoworkshop.ximix.node;

import org.cryptoworkshop.ximix.common.util.ExtendedFuture;

/**
 *
 */
public class NodeStoppedFuture extends ExtendedFuture<XimixNodeContext>
{
    public NodeStoppedFuture(XimixNodeContext value)
    {
        setValue(value);
    }

    @Override
    public boolean cancel(boolean mayInterruptIfRunning)
    {
        throw new RuntimeException("Stop cannot be canceled.");
    }

    @Override
    public boolean isCancelled()
    {
        return false;
    }


}
