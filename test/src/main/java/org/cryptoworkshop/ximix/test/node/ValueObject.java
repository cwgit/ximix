package org.cryptoworkshop.ximix.test.node;

/**
 *   Utility class to allow setting of values from within inner classes and situations where
 *   the actual instance may be declared final.
 */
public class ValueObject<T>
{
    private T value;

    public ValueObject()
    {
        value = null;
    }

    public ValueObject(T initValue)
    {
        this.value = initValue;
    }


    public T get()
    {
        return value;
    }

    public void set(T newValue)
    {
        this.value = newValue;
    }


}
