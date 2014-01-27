package org.cryptoworkshop.ximix.common.util.challenge;

import java.util.BitSet;

import org.cryptoworkshop.ximix.common.util.IndexNumberGenerator;

/**
 * This challenger is based on the paired link breaking challenger in "Making Mix Nets Robust For Electronic Voting By Randomized Partial Checking"
 * by Markus Jakobsson, Ari Juels, Ronald L. Rivest, 11th USENIX Security Symposium, 2002. Figure 1. Section 1.1.
 */
public class PairedChallenger
    implements IndexNumberGenerator
{
    private final int[] indexes;
    private final BitSet bitSet;

    private int max;
    private int counter;
    private int startIndex;
    private boolean isEvenCall;
    private int stepNo;

    /**
     * Base Constructor.This creates a challenger with an initial isEvenCall state set to false.
     *
     * @param indexes the mappings from the first board to the second one in the pair..
     * @param stepNo initial step number.
     * @param firstPartIndexes the generator to provide the indexes for the first of the pairing.
     */
    public PairedChallenger(int[] indexes, int stepNo, IndexNumberGenerator firstPartIndexes)
    {
        this.indexes = indexes;

        this.bitSet = new BitSet(indexes.length);
        int count = 0;
        while (firstPartIndexes.hasNext())
        {
            count++;
            bitSet.set(firstPartIndexes.nextIndex());
        }

        this.max = count;
        this.isEvenCall = false;
        this.stepNo = stepNo;
    }

    /**
     * Set the current stepNo. If this is different from the previous one the challenger will be reset
     * and the internal isEvenCall flag flipped.
     *
     * @param stepNo the current step number.
     */
    public void setStepNo(int stepNo)
    {
        if (this.stepNo != stepNo)
        {
            startIndex = 0;
            counter = 0;
            isEvenCall = !isEvenCall;
            max = indexes.length - max;
            this.stepNo = stepNo;
        }
    }

    @Override
    public synchronized boolean hasNext()
    {
        return counter != max;
    }

    @Override
    public synchronized int nextIndex()
    {
        int ret = (isEvenCall) ? bitSet.nextClearBit(startIndex) : bitSet.nextSetBit(startIndex);

        startIndex = ret + 1;

        counter++;

        if (isEvenCall)
        {
            return indexes[ret];
        }

        return ret;
    }
}
