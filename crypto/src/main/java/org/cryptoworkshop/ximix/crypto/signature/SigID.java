package org.cryptoworkshop.ximix.crypto.signature;

public class SigID
{
    private final String id;

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
