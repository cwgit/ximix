package org.cryptoworkshop.ximix.node.mixnet.test;

import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;
import org.bouncycastle.asn1.DEROctetString;
import org.cryptoworkshop.ximix.common.util.IndexNumberGenerator;
import org.cryptoworkshop.ximix.common.util.challenge.SeededChallenger;
import org.junit.Test;

/**
 *
 */
public class SeededChallengerTest
    extends TestCase
{
    @Test
    public void testChallengerCoverage()
        throws Exception
    {
        Set<Integer> sample = new HashSet<>();

        for (int i = 0; i != 1000; i++)
        {
            sample.add(i);
        }

        IndexNumberGenerator ind = new SeededChallenger(1000, 0, new DEROctetString(new byte[55]).getEncoded());

        while (ind.hasNext())
        {
            sample.remove(ind.nextIndex());
        }

        TestCase.assertEquals(500, sample.size());

        ind = new SeededChallenger(1000, 1, new DEROctetString(new byte[55]).getEncoded());

        while (ind.hasNext())
        {
            sample.remove(ind.nextIndex());
        }

        TestCase.assertEquals(0, sample.size());
    }

    @Test
    public void testChallengerCoverageOddSamples()
        throws Exception
    {
        Set<Integer> sample = new HashSet<>();

        for (int i = 0; i != 1001; i++)
        {
            sample.add(i);
        }

        IndexNumberGenerator ind = new SeededChallenger(1001, 0, new DEROctetString(new byte[55]).getEncoded());

        while (ind.hasNext())
        {
            sample.remove(ind.nextIndex());
        }

        TestCase.assertEquals(500, sample.size());

        ind = new SeededChallenger(1001, 1, new DEROctetString(new byte[55]).getEncoded());

        while (ind.hasNext())
        {
            sample.remove(ind.nextIndex());
        }

        TestCase.assertEquals(0, sample.size());
    }
}
