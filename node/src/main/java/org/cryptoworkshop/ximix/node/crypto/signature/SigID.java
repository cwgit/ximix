package org.cryptoworkshop.ximix.node.crypto.signature;

/**
 * Object based key to identify particular signing operations.
 */
public class SigID
{
    private final String id;

    /**
     * Base constructor.
     *
     * @param id  an ID associated with a signing operation.
     */
    public SigID(String id)
    {
        this.id = id;
    }

    public String getID()
    {
        return id;
    }

    public int hashCode()
    {
        return id.hashCode();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof SigID)
        {
            SigID other = (SigID)o;

            return this.id.equals(other.id);
        }

        return false;
    }
}
