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
        ShamirSecretSplitter secretSplitter = new ShamirSecretSplitter(numberOfPeers, threshold, domainParams.getN());

        // Having created a private key the server creates shares of that
        // private key. It would keep one share for itself and sends the others
        // shares to the other servers.
        BigInteger[][] privateKeyShares = new BigInteger[numberOfPeers][];
        BigInteger[] finalPrivateKeyShares = new BigInteger[numberOfPeers];
        for (int i = 0; i < numberOfPeers; i++)
        {
            privateKeyShares[i] = secretSplitter.split(((ECPrivateKeyParameters)kps[i].getPrivate()).getD(), new SecureRandom()).getShares();
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
