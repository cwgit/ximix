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
package org.cryptoworkshop.ximix.common.crypto;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Commitment;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.commitments.HashCommitter;

/**
 * Basic hash-based committer which operates on 4 bytes integers.
 */
public class IndexCommitter
{
    private HashCommitter committer;

    /**
     * Constructor for generating commitments.
     *
     * @param digest the digest to base the HashCommitter on.
     * @param random the SecureRandom to use for generating witness values.
     */
    public IndexCommitter(ExtendedDigest digest, SecureRandom random)
    {
        committer = new HashCommitter(digest, random);
    }

    /**
     * Constructor for verifying commitments.
     *
     * @param digest the digest to base the HashCommitter on.
     */
    public IndexCommitter(ExtendedDigest digest)
    {
        committer = new HashCommitter(digest, null);
    }

    /**
     * Generate a commitment for a passed in index.
     *
     * @param index the index to commit to.
     * @return a hash based commitment.
     */
    public Commitment commit(int index)
    {
        return committer.commit(toBytes(index));
    }

    /**
     * Return true if the passed in commitment is for index.
     *
     * @param commitment a hash based commitment for an index,
     * @param index the index we wish to verify against.
     * @return true if the commitment matches the index, false otherwise.
     */
    public boolean isRevealed(Commitment commitment, int index)
    {
        return committer.isRevealed(commitment, toBytes(index));
    }

    private byte[] toBytes(int index)
    {
        byte[] v = new byte[4];

        v[0] = (byte)(index >>> 24);
        v[1] = (byte)(index >>> 16);
        v[2] = (byte)(index >>> 8);
        v[3] = (byte)index;

        return v;
    }
}
