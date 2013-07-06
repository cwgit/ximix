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
package org.cryptoworkshop.ximix.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.ec.ECElGamalEncryptor;
import org.bouncycastle.crypto.ec.ECEncryptor;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.crypto.threshold.LagrangeWeightCalculator;
import org.cryptoworkshop.ximix.crypto.threshold.ShamirSecretSplitter;
import org.cryptoworkshop.ximix.crypto.threshold.SplitSecret;
import org.junit.Assert;
import org.junit.Test;

public class BasicShamirSharingTest
{
    @Test
    public void testBasicThreshold5()
    {
        doTestOnPeers(5);
    }

    @Test
    public void testBasicThreshold6()
    {
        doTestOnPeers(6);
    }

    @Test
    public void testMultiplicationProtocol()
    {
        X9ECParameters params = SECNamedCurves.getByName("secp256r1");
        SecureRandom random = new SecureRandom();

        ECDomainParameters domainParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed());

        int numberOfPeers = 10;
        int threshold = 3;
        BigInteger p = params.getN();

        ShamirSecretSplitter secretSplitter = new ShamirSecretSplitter(numberOfPeers, threshold, p, random);

        // The k shares
        //
        BigInteger[] kVals = new BigInteger[numberOfPeers];
        BigInteger[][] kShares = new BigInteger[numberOfPeers][];
        for (int i = 0; i < numberOfPeers; i++)
        {
            kVals[i] = getRandomInteger(p, random);
            SplitSecret split = secretSplitter.split(kVals[i]);

            kShares[i] = split.getShares();
        }

        BigInteger kVal = BigInteger.ZERO;
        for (BigInteger v : kVals)
        {
            kVal = kVal.add(v).mod(p);
        }
        BigInteger k = computeValue(numberOfPeers, threshold, p, kShares);
        BigInteger[] weights;
        BigInteger[] finalKShares = new BigInteger[numberOfPeers];
        for (int i = 0; i < numberOfPeers; i++)
        {
            finalKShares[i] = kShares[0][i];
            for (int j = 1; j < numberOfPeers; j++)
            {
                finalKShares[i] = finalKShares[i].add(kShares[j][i]);
            }
        }
        //
        // divided by numberOfPeers as numberOfPeers polynomials
        Assert.assertEquals(k, kVal);

        // The a shares
        //
        BigInteger[] aVals = new BigInteger[numberOfPeers];
        BigInteger[][] aShares = new BigInteger[numberOfPeers][];
        for (int i = 0; i < numberOfPeers; i++)
        {
            aVals[i] = getRandomInteger(params.getN(), random);
            aShares[i] = secretSplitter.split(aVals[i]).getShares();
        }

        BigInteger aVal = BigInteger.ZERO;
        for (BigInteger v : aVals)
        {
            aVal = aVal.add(v).mod(p);
        }
        BigInteger a = computeValue(numberOfPeers, threshold, p, aShares);
        BigInteger[] finalAShares = new BigInteger[numberOfPeers];
        for (int i = 0; i < numberOfPeers; i++)
        {
            finalAShares[i] = aShares[0][i];
            for (int j = 1; j < numberOfPeers; j++)
            {
                finalAShares[i] = finalAShares[i].add(aShares[j][i]);
            }
        }
        //
        // divided by numberOfPeers as numberOfPeers polynomials
        Assert.assertEquals(a, aVal);

        // create the splitter for the peers/threshold over the order of the curve.
        secretSplitter = new ShamirSecretSplitter(numberOfPeers, 2 * threshold, domainParams.getN(), random);

        // The z shares
        //
        BigInteger[][] zShares = new BigInteger[numberOfPeers][];

        for (int i = 0; i < numberOfPeers; i++)
        {
            zShares[i] = secretSplitter.split(BigInteger.ZERO).getShares();
        }

        BigInteger[] finalZShares = new BigInteger[numberOfPeers];
        for (int i = 0; i < numberOfPeers; i++)
        {
            finalZShares[i] = zShares[0][i];
            for (int j = 1; j < numberOfPeers; j++)
            {
                finalZShares[i] = finalZShares[i].add(zShares[j][i]);
            }
        }
        // Simulates distributing shares and combining them
        // v(i) = k(i)a(i) + z(i)
//        BigInteger[] finalVShares = new BigInteger[numberOfPeers];
//        for (int i = 0; i < numberOfPeers; i++)
//        {
//            finalVShares[i] = kShares[0][i].multiply(aShares[0][i]).add(zShares[0][i]).mod(p);
//            for (int j = 1; j < numberOfPeers; j++)
//            {
//                finalVShares[i] = finalVShares[i].add(kShares[j][i].multiply(aShares[j][i]).add(zShares[j][i])).mod(p);
//            }
//        }

        BigInteger[] finalVShares = new BigInteger[numberOfPeers];

            for (int i = 0; i < numberOfPeers; i++)
            {
                finalVShares[i] = finalKShares[i].multiply(finalAShares[i]).add(finalZShares[i]).mod(p);
            }

        BigInteger[] alpha = new BigInteger[numberOfPeers];
        for (int i = 0; i < numberOfPeers; i++)
        {
            alpha[i] = BigInteger.valueOf(i + 1);
        }

//        BWDecoder bwDecU = new BWDecoder(
//      				alpha,
//      				finalVShares,
//      			    2 * threshold,
//      				p);
//      	BigInteger mu1 = bwDecU.interpolate(BigInteger.ZERO);

        //
        // in this case these should come out the same.
        LagrangeWeightCalculator lagrangeWeightCalculator = new LagrangeWeightCalculator(numberOfPeers, domainParams.getN());
        BigInteger[] weights1 = lagrangeWeightCalculator.computeWeights(finalVShares);

        BigInteger mu2 = finalVShares[0].multiply(weights1[0]).mod(p);
        for (int i = 1; i < weights1.length; i++)
        {
            if (finalVShares[i] != null)
            {
               mu2 = mu2.add(finalVShares[i].multiply(weights1[i])).mod(p);
            }
        }

       // Assert.assertEquals(mu1, mu2);

        //
        // check values for mu
        //
        Assert.assertEquals(mu2, k.multiply(a).mod(p));
    }

    private BigInteger computeValue(int numberOfPeers, int threshold, BigInteger p, BigInteger[][] shares)
    {
        LagrangeWeightCalculator lagrangeWeightCalculator = new LagrangeWeightCalculator(numberOfPeers, p);

        BigInteger[] finalShares = new BigInteger[numberOfPeers];
        for (int i = 0; i < numberOfPeers; i++)
        {
            finalShares[i] = shares[0][i];
            for (int j = 1; j < numberOfPeers; j++)
            {
                finalShares[i] = finalShares[i].add(shares[j][i]).mod(p);
            }
        }

        BigInteger[] weights = lagrangeWeightCalculator.computeWeights(finalShares);

        BigInteger rv = finalShares[0].multiply(weights[0]);
        for (int i = 1; i < weights.length; i++)
        {
            if (finalShares[i] != null)
            {
                rv = rv.add(finalShares[i].multiply(weights[i]).mod(p)).mod(p);
            }
        }
        return rv;
    }

    private void doTestOnPeers(int numberOfPeers)
    {
        X9ECParameters params = SECNamedCurves.getByName("secp256r1");

        ECKeyPairGenerator kpGen = new ECKeyPairGenerator();

        ECDomainParameters domainParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed());

        kpGen.init(new ECKeyGenerationParameters(domainParams, new SecureRandom()));

        AsymmetricCipherKeyPair[] kps = new AsymmetricCipherKeyPair[numberOfPeers];

        // Generate Private Keys - normally this would be done by each
        // individual server. For this example we will just create them in an
        // array.
        for (int i = 0; i < kps.length; i++)
        {
            kps[i] = kpGen.generateKeyPair();
        }

        doTest(domainParams, kps, numberOfPeers - 1, true, 1);
        doTest(domainParams, kps, numberOfPeers - 2, true, 1);
        doTest(domainParams, kps, numberOfPeers - 2, true, 1, 3);
        doTest(domainParams, kps, numberOfPeers - 1, false, 1, 3);
    }

    private void doTest(ECDomainParameters domainParams, AsymmetricCipherKeyPair[] kps, int threshold, boolean shouldPass, int... missing)
    {
        int numberOfPeers = kps.length;

        // create the splitter for the peers/threshold over the order of the curve.
        ShamirSecretSplitter secretSplitter = new ShamirSecretSplitter(numberOfPeers, threshold, domainParams.getN(), new SecureRandom());

        // Having created a private key the server creates shares of that
        // private key. It would keep one share for itself and sends the others
        // shares to the other servers.
        BigInteger[][] privateKeyShares = new BigInteger[numberOfPeers][];
        BigInteger[] finalPrivateKeyShares = new BigInteger[numberOfPeers];
        for (int i = 0; i < numberOfPeers; i++)
        {
            privateKeyShares[i] = secretSplitter.split(((ECPrivateKeyParameters)kps[i].getPrivate()).getD()).getShares();
        }

        // Simulates distributing shares and combining them
        for (int i = 0; i < numberOfPeers; i++)
        {
            finalPrivateKeyShares[i] = privateKeyShares[0][i];
            for (int j = 1; j < numberOfPeers; j++)
            {
                finalPrivateKeyShares[i] = finalPrivateKeyShares[i].add(privateKeyShares[j][i]);
            }
        }

        ECPoint pubPoint = ((ECPublicKeyParameters)kps[0].getPublic()).getQ();

        for (int i = 1; i < numberOfPeers; i++)
        {
            pubPoint = pubPoint.add(((ECPublicKeyParameters)kps[i].getPublic()).getQ());
        }

        ECPublicKeyParameters jointPub = new ECPublicKeyParameters(pubPoint, domainParams);

        // Create a random plaintext
        ECPoint plaintext = generatePoint(domainParams, new SecureRandom());

        // Encrypt it using the joint public key
        ECEncryptor enc = new ECElGamalEncryptor();

        enc.init(new ParametersWithRandom(jointPub, new SecureRandom()));

        ECPair cipherText = enc.encrypt(plaintext);

        // do partial decrypts
        ECPoint[] partialDecs = new ECPoint[numberOfPeers];

        for (int i = 0; i < numberOfPeers; i++)
        {
            partialDecs[i] = cipherText.getX().multiply(finalPrivateKeyShares[i]);
        }

        // simulate missing peers
        for (int i = 0; i != missing.length; i++)
        {
            partialDecs[missing[i]] = null;
        }

        // decryption step
        LagrangeWeightCalculator lagrangeWeightCalculator = new LagrangeWeightCalculator(numberOfPeers, domainParams.getN());

        BigInteger[] weights = lagrangeWeightCalculator.computeWeights(partialDecs);

        // weighting
        ECPoint weightedDecryption = partialDecs[0].multiply(weights[0]);
        for (int i = 1; i < weights.length; i++)
        {
            if (partialDecs[i] != null)
            {
                weightedDecryption = weightedDecryption.add(partialDecs[i].multiply(weights[i]));
            }
        }

        // Do final decryption to recover plaintext ECPoint
        ECPoint decrypted = cipherText.getY().add(weightedDecryption.negate());

        Assert.assertEquals(shouldPass, plaintext.equals(decrypted));
    }

    public static BigInteger getRandomInteger(BigInteger n, SecureRandom rand)
    {
        BigInteger r;
        int maxbits = n.bitLength();
        do
        {
            r = new BigInteger(maxbits, rand);
        }
        while (r.compareTo(n) >= 0);
        return r;
    }

    public static ECPoint generatePoint(ECDomainParameters params, SecureRandom rand)
    {
        return params.getG().multiply(getRandomInteger(params.getN(), rand));
    }
}
