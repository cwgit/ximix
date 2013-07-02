package org.cryptoworkshop.ximix.common.util;

import java.util.concurrent.*;

/**
 * Extends the standard future interface and adds sync methods.
 * Adds the concepts of syncing and call backs to the standard Future.
 * To allow simple blocking for an outcome to occur.
 */
public abstract class ExtendedFuture<T> implements Future<T>
{
    protected CountDownLatch latch = null;
    protected T value = null;
    protected Throwable executionException = null;
    protected boolean timedOut = false;

    protected FutureComplete<T> completedHandler = null;


    public ExtendedFuture()
    {
        latch = new CountDownLatch(1);
    }

    public synchronized ExtendedFuture<T> withHandler(FutureComplete<T> completedHandler)
    {
        this.completedHandler = completedHandler;
        return this;
    }

    public synchronized void setValue(T value)
    {
        this.value = value;
    }

    public synchronized void finish()
    {
        finish(null);
    }

    public synchronized void finish(T finalValue)
    {
        this.value = finalValue;
        if (this.completedHandler != null)
        {
            completedHandler.handle(this);
        }
        latch.countDown();
    }

    protected synchronized void timedOut()
    {
       timedOut(null);
    }

    protected synchronized void timedOut(T finalValue)
    {
        timedOut = true;
        this.value = finalValue;

        if (completedHandler != null)
        {
            completedHandler.handle(this);
        }

        latch.countDown();
    }

    protected synchronized  void failed(Throwable th)
    {
        failed(th, null);
    }


    protected synchronized void failed(Throwable th, T value)
    {
        executionException = th;
        this.value = value;

        if (completedHandler != null)
        {
            completedHandler.handle(this);
        }

        latch.countDown();
    }


    public boolean isTimedOut()
    {
        return timedOut;
    }

    public void setExecutionException(Throwable executionException)
    {
        this.executionException = executionException;
    }

    @Override
    public abstract boolean cancel(boolean mayInterruptIfRunning);

    @Override
    public abstract boolean isCancelled();

    @Override
    public synchronized  boolean isDone()
    {
        return latch.getCount() == 0;
    }

    @Override
    public synchronized T get() throws InterruptedException, ExecutionException
    {
        return value;
    }

    @Override
    public synchronized T get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException
    {
        if (latch.await(timeout, unit))
        {
            return value;
        }
        throw new TimeoutException();
    }

    /**
     * Wait until completed.
     *
     * @throws InterruptedException
     */
    public void sync() throws InterruptedException
    {
        latch.await();
    }

    /**
     * Wait for future to complete, returns false if the waiting period below timed out.
     *
     * @param timeout
     * @param timeunit
     * @return true of the event occurs, false if it timesout.
     * @throws InterruptedException
     */
    public boolean sync(int timeout, TimeUnit timeunit) throws InterruptedException
    {
        return latch.await(timeout, timeunit);
    }


}


