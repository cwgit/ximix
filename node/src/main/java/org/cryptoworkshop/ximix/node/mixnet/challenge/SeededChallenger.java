/**
 * Copyright 2013 Crypto Workshop Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.cryptoworkshop.ximix.node.mixnet.challenge;

import java.util.BitSet;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.EntropySourceProvider;
import org.bouncycastle.crypto.prng.drbg.HashSP800DRBG;
import org.bouncycastle.crypto.prng.drbg.SP80090DRBG;
import org.cryptoworkshop.ximix.node.mixnet.util.IndexNumberGenerator;

/**
 * A challenger uses a provided seed in conjunction with a hash function
 * to provide challenges for just under or equal to 50% of the bulletin board contents.
 * <p>
 * As the step number increments the challenger mirrors its internal bitset in order to provide
 * fullest coverage of the over 2 sets of challenges.
 * </p>
 */
public class SeededChallenger
    implements IndexNumberGenerator
{
    private final int max;
    private final BitSet bitSet;
    private final boolean isMirror;

    private int counter;
    private int startIndex;

    /**
     * Base constructor.
     *
     * @param size the number of messages on the board we are issuing challenges on.
     * @param stepNo the number of the step in the shuffling process.
     * @param seed a random seed for creating index numbers to challenge on - must be at least 55 bytes.
     */
    public SeededChallenger(Integer size, Integer stepNo, byte[] seed)
    {
        this.max = size / 2;
        this.counter = 0;
        this.startIndex = 0;

        this.bitSet = buildBitSet(size, new HashSP800DRBG(new SHA256Digest(), 256, new SingleEntropySourceProvider(seed).get(440), null, null));
        this.isMirror = (((seed[seed.length - 1] & 0xff) + stepNo) & 0x01) == 0;
    }

    @Override
    public synchronized boolean hasNext()
    {
        return counter != max;
    }

    @Override
    public synchronized int nextIndex()
    {
        int ret = (isMirror) ?  bitSet.nextClearBit(startIndex) : bitSet.nextSetBit(startIndex);

        startIndex = ret + 1;

        counter++;

        return ret;
    }

    private BitSet buildBitSet(int size, SP80090DRBG drbg)
    {
        BitSet bitSet = new BitSet(size);

        int upper = size - 1;
        int lower = 0;

        for (int i = 0; i != max; i++)
        {
            int nIndex = nextInt(drbg, upper - lower + 1) + lower;

            if (bitSet.get(nIndex))
            {
                if ((nIndex & 1) != 0)
                {
                    while (bitSet.get(upper))
                    {
                        upper--;
                    }

                    nIndex = upper--;
                }
                else
                {
                    while (bitSet.get(lower))
                    {
                        lower++;
                    }

                    nIndex = lower++;
                }
            }

            bitSet.set(nIndex);
        }

        return bitSet;
    }

    // the classic unbiased sampler
    private int nextInt(SP80090DRBG drbg, int range)
    {
        if ((range & -range) == range)  // i.e., range is a power of 2
        {
            return (int)((range * (long)makePositiveInt(drbg)) >> 31);
        }

        int bits, val;
        do
        {
            bits = makePositiveInt(drbg);
            val = bits % range;
        }
        while (bits - val + (range - 1) < 0);

        return val;
    }

    private int makePositiveInt(SP80090DRBG drbg)
    {
        byte[] bytes = new byte[4];

        drbg.generate(bytes, null, false);

        return ((bytes[0] & 0x7f) << 24) | ((bytes[1] & 0xff) << 16) | ((bytes[2] & 0xff) << 8) | (bytes[3] & 0xff);
    }

    private class SingleEntropySourceProvider
        implements EntropySourceProvider
    {
        private final byte[] data;

        protected SingleEntropySourceProvider(byte[] data)
        {
            this.data = data;
        }

        public EntropySource get(final int bitsRequired)
        {
            return new EntropySource()
            {
                int index = 0;

                public boolean isPredictionResistant()
                {
                    return true;
                }

                public byte[] getEntropy()
                {
                    byte[] rv = new byte[bitsRequired / 8];

                    if (data.length < (index + rv.length))
                    {
                        throw new IllegalStateException("Insufficient entropy - need " + rv.length + " bytes for challenge seed.");
                    }

                    System.arraycopy(data, index, rv, 0, rv.length);

                    index += bitsRequired / 8;

                    return rv;
                }

                public int entropySize()
                {
                    return bitsRequired;
                }
            };
        }
    }
}
