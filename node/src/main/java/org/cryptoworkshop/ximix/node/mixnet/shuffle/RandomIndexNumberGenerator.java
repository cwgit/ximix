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
package org.cryptoworkshop.ximix.node.mixnet.shuffle;

import java.security.SecureRandom;
import java.util.BitSet;

import org.cryptoworkshop.ximix.common.util.IndexNumberGenerator;

/**
 * A generator of index numbers that covers a range of 0 to (size - 1). The generator uses an
 * underlying BitSet to make sure no number is generated twice.
 */
public class RandomIndexNumberGenerator
    implements IndexNumberGenerator
{
    private final SecureRandom random;
    private final int size;

    private final BitSet bitSet;

    private int upper;
    private int lower;

    /**
     * Base constructor.
     *
     * @param size the number of messages on the board we are trying to generate indexes for.
     * @param random a source of randomness.
     */
    public RandomIndexNumberGenerator(int size, SecureRandom random)
    {
        this.size = size;
        this.random = random;

        this.upper = size - 1;
        this.lower = 0;
        this.bitSet = new BitSet(size);
    }

    public boolean hasNext()
    {
        return bitSet.nextClearBit(lower) <= upper;
    }

    public int nextIndex()
    {
        int nIndex = random.nextInt(upper - lower + 1) + lower;

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
        return nIndex;
    }
}
