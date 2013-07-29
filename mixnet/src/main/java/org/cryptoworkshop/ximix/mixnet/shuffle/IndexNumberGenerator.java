package org.cryptoworkshop.ximix.mixnet.shuffle;

public class IndexNumberGenerator
{
    private final int maxIndex;

    public IndexNumberGenerator(int size)
    {
        this.maxIndex = size - 1;
    }

    public int nextIndex(int index)
    {
        return maxIndex - index;
    }
}
