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
    protected  boolean timedOut = false;

    protected FutureComplete<T> completedHandler = null;
    protected FutureComplete<T> onThrowable = null;
    protected FutureComplete<T> onTimeOut = null;

    public ExtendedFuture()
    {
        latch = new CountDownLatch(1);
    }

    public ExtendedFuture<T> onComplete(FutureComplete<T> completedHandler)
    {
        this.completedHandler = completedHandler;
        return this;
    }


    public ExtendedFuture<T> onThrowable(FutureComplete<T> onThrowable)
    {
        this.onThrowable = onThrowable;
        return this;
    }

    public ExtendedFuture<T> onTimeOut(FutureComplete<T> onTimeOut)
    {
        this.onTimeOut = onTimeOut;
        return this;
    }


    public void setValue(T value)
    {
        this.value = value;
    }

    public void finish()
    {
        finish(null);
    }

    public void finish(T finalValue)
    {
        this.value = finalValue;
        latch.countDown();
    }

    protected void timedOut()
    {
       timedOut(null);
    }

    protected void timedOut(T finalValue)
    {
        timedOut = true;
        this.value = finalValue;
        latch.countDown();
    }

    protected void failed(Throwable th)
    {
        failed(th, null);
    }


    protected void failed(Throwable th, T value)
    {
        executionException = th;
        this.value = value;

        if (onThrowable != null)
        {
            onThrowable.handle(this);
        }

        latch.countDown();
    }


    @Override
    public abstract boolean cancel(boolean mayInterruptIfRunning);

    @Override
    public abstract boolean isCancelled();

    @Override
    public boolean isDone()
    {
        return latch.getCount() == 0;
    }

    @Override
    public T get() throws InterruptedException, ExecutionException
    {
        return value;
    }

    @Override
    public T get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException
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


