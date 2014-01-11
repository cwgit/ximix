package org.cryptoworkshop.ximix.node.mixnet.challenge;

import java.util.BitSet;
import java.util.Enumeration;

import org.cryptoworkshop.ximix.common.asn1.message.MessageCommitment;
import org.cryptoworkshop.ximix.common.asn1.message.PostedData;
import org.cryptoworkshop.ximix.common.asn1.message.TranscriptBlock;
import org.cryptoworkshop.ximix.common.util.TranscriptType;
import org.cryptoworkshop.ximix.node.mixnet.board.BulletinBoard;
import org.cryptoworkshop.ximix.node.mixnet.util.IndexNumberGenerator;

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
     * @param initialBoard the initial board to work out the paired index sets.
     * @param stepNo initial step number.
     * @param firstPartIndexes the generator to provide the indexes for the first of the pairing.
     */
    public PairedChallenger(BulletinBoard initialBoard, int stepNo, IndexNumberGenerator firstPartIndexes)
    {
        // TODO: maybe configure chunksize
        int chunkSize = 100;
        IndexNumberGenerator sourceGenerator = new SerialChallenger(initialBoard.size(), 0, null);
        System.err.println(stepNo);
        indexes = new int[initialBoard.size()];
        int count = 0;
        while (sourceGenerator.hasNext())
        {
            TranscriptBlock transcript = initialBoard.fetchTranscriptData(TranscriptType.WITNESSES, sourceGenerator, new TranscriptBlock.Builder(0, chunkSize));

            for (Enumeration en = transcript.getDetails().getObjects(); en.hasMoreElements();)
            {
                PostedData msg = PostedData.getInstance(en.nextElement());

                indexes[count++] = MessageCommitment.getInstance(msg.getData()).getNewIndex();
            }
        }

        this.bitSet = new BitSet(indexes.length);
        count = 0;
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
