package org.cryptoworkshop.ximix.common.crypto;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Commitment;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.commitments.HashCommitter;

public class IndexCommitter
{
    private HashCommitter committer;

    public IndexCommitter(ExtendedDigest digest, SecureRandom random)
    {
        committer = new HashCommitter(digest, random);
    }

    public IndexCommitter(ExtendedDigest digest)
    {
        committer = new HashCommitter(digest, null);
    }

    public Commitment commit(int index)
    {
        return committer.commit(toBytes(index));
    }

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
