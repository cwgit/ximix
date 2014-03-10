package org.cryptoworkshop.ximix.demo.ballot;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Map;
import java.util.TreeMap;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * A basic ballot packer to produce simple files compatible with the Surrey format - the file maps a set of permutations to a
 * random EC point. Permutations such as "2,2,2" are allowed.
 */
public class PackedBallotTableBuilder
{
    private final byte[] seed;
    private final int maxBallotSize;
    private final int packingLevel;
    private final ECDomainParameters domainParameters;
    private final Map<ECPoint, byte[]> packMap = new TreeMap<>(new Comparator<ECPoint>()
            {
                @Override
                public int compare(ECPoint ecPoint1, ECPoint ecPoint2)
                {
                    byte[] ec1 = ecPoint1.getEncoded(true);
                    byte[] ec2 = ecPoint2.getEncoded(true);

                    // length actually appears constant in Surrey code as a full line length buffer is used.
//                    if (ec1.length != ec2.length)
//                    {
//                        return ec1.length - ec2.length;
//                    }

                    for (int i = 0; i != ec1.length; i++)
                    {
                        int diff = (ec1[i] - ec2[i]);
                        if (diff != 0)
                        {
                            return diff;
                        }
                    }

                    return 0;
                }
            });

    /**
     * Base constructor.
     *
     * @param seed a random seed to base the packing data on.
     * @param domainParameters domain parameters for the curve we're using
     * @param maxBallotSize longest ballot (i.e. number of candidates), this table will be used with.
     * @param packingLevel the number of permutations to be included in each ballot.
     */
    public PackedBallotTableBuilder(byte[] seed, ECDomainParameters domainParameters, int maxBallotSize, int packingLevel)
    {
        this.seed = seed.clone();
        this.domainParameters = domainParameters;
        this.maxBallotSize = maxBallotSize;
        this.packingLevel = packingLevel;
    }

    /**
     * Build a packing table into the stream out.
     *
     * @param out  output stream to put the packed data into.
     * @return the padding point - a point that maps to a permutation of all zeroes.
     * @throws IOException
     */
    public ECPoint build(OutputStream out)
        throws IOException
    {
        SHA256Digest     digest = new SHA256Digest();

        byte[] ballot = new byte[packingLevel];
        byte[] hash = new byte[digest.getDigestSize()];

        long tot = 1;
        for (int p = 0; p != packingLevel; p++)
        {
            tot *= maxBallotSize;

            Arrays.fill(ballot, (byte)0);

            for (int i = 1; i <= p; i++)
            {
                ballot[i] = 1;
            }

            for (int k = 0; k != tot; k++)
            {
                incrementBallot(ballot);

                ECPoint point = generatePackPoint(digest, ballot, hash);

                packMap.put(point, ballot.clone());
            }
        }

        BufferedOutputStream bufOut = new BufferedOutputStream(out);
        byte[] packing = new byte[36];

        for (ECPoint key : packMap.keySet())
        {
            byte[] encoded = key.getEncoded(true);
            byte[] prefs = packMap.get(key);

            bufOut.write(encoded);

            bufOut.write(prefs);

            int outLen = encoded.length + prefs.length;
            if (outLen != 36)
            {
                bufOut.write(packing, 0, 36 - outLen);
            }
        }

        bufOut.flush();

        return generatePackPoint(digest, ballot, hash);   // point to use to represent all zeroes.
    }

    Map<ECPoint, byte[]> getPackingMap()
    {
        return packMap;
    }

    private ECPoint generatePackPoint(SHA256Digest digest, byte[] ballot, byte[] hash)
    {
        BigInteger element;
        ECPoint point;
        do
        {
            digest.update(seed, 0, seed.length);

            for (int b = 0; b != ballot.length; b++)
            {
                digest.update(ballot[b]);
            }

            digest.doFinal(hash, 0);

            digest.update(hash, 0, hash.length);

            element = new BigInteger(1, hash).mod(domainParameters.getN());
            point = domainParameters.getG().multiply(element).normalize();
        }
        while (element.equals(BigInteger.ZERO) || packMap.containsKey(point));
        return point;
    }

    private void incrementBallot(byte[] ballot)
    {
        ballot[0]++;
        for (int i = 0; i != ballot.length - 1; i++)
        {
            if (ballot[i] > maxBallotSize)
            {
                ballot[i] = 1;
                ballot[i + 1]++;
            }
        }
    }
}
