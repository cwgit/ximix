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
package org.cryptoworkshop.ximix.client.verify;

import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.common.asn1.message.ChallengeLogMessage;
import org.cryptoworkshop.ximix.common.crypto.threshold.LagrangeWeightCalculator;

/**
 * Verifier for a decryption challenge log stream
 */
public class ECDecryptionChallengeVerifier
{
    private final ECPublicKeyParameters pubKey;
    private final InputStream logStream;

    private ECPublicKeyParameters[] activePeers = new ECPublicKeyParameters[0];
    private int maxSequenceNo = 0;

    /**
     * Base constructor.
     *
     * @param pubKey the public key that we are verifying against.
     * @param logStream InputStream representing the decryption challenge transcript.
     */
    public ECDecryptionChallengeVerifier(ECPublicKeyParameters pubKey, InputStream logStream)
    {
        this.pubKey = pubKey;
        this.logStream = logStream;
    }

    /**
     * Verify that the decryption challenge transcript is valid, throwing an exception if an issue is found..
     *
     * @throws TranscriptVerificationException on verification failure.
     */
    public void verify()
        throws TranscriptVerificationException
    {
        ASN1InputStream aIn = new ASN1InputStream(logStream);

        try
        {
            int messageIndex = -1;

            ASN1Object obj;
            while ((obj = aIn.readObject()) != null)
            {
                ChallengeLogMessage logMessage = ChallengeLogMessage.getInstance(obj);

                ECPoint[] sourceMessage = logMessage.getSourceMessage();
                ECPoint[] challengeResults = logMessage.getChallengeResult();

                ECPublicKeyParameters currentPubKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(logMessage.getKeyInfo());
                if (!isSameParameters(pubKey.getParameters(), currentPubKey.getParameters()))
                {
                    throw new TranscriptVerificationException("Log message indicates inconsistent public key parameters.");
                }

                if (messageIndex != logMessage.getIndex())
                {
                    // verify the partial public keys represent the one we have.
                    if (activePeers.length != 0)
                    {
                        LagrangeWeightCalculator weightCalculator = new LagrangeWeightCalculator(maxSequenceNo + 1, pubKey.getParameters().getN());

                        ECPoint accumulatedQ = null;

                        BigInteger[] weights = weightCalculator.computeWeights(activePeers);

                        for (int i = 0; i != weights.length; i++)
                        {
                             if (weights[i] != null)
                             {
                                 if (accumulatedQ == null)
                                 {
                                     accumulatedQ = activePeers[i].getQ().multiply(weights[i]);
                                 }
                                 else
                                 {
                                     accumulatedQ = accumulatedQ.add(activePeers[i].getQ().multiply(weights[i]));
                                 }
                             }
                        }
                        if (!pubKey.getQ().equals(accumulatedQ))
                        {
                            throw new TranscriptVerificationException("Log message indicates inconsistent public key.");
                        }
                        // reset the peers array.
                        for (int i = 0; i != activePeers.length; i++)
                        {
                            activePeers[i] = null;
                        }
                    }

                    messageIndex = logMessage.getIndex();
                }

                addPeer(logMessage.getSequenceNo(), currentPubKey);

                if (!logMessage.hasPassed())
                {
                    throw new TranscriptVerificationException("Log message indicates challenge did not pass.");
                }

                for (int i = 0; i != sourceMessage.length; i++)
                {
                    sourceMessage[i] = sourceMessage[i].multiply(logMessage.getM());
                }

                if (!Arrays.equals(sourceMessage, challengeResults))
                {
                    throw new TranscriptVerificationException("Challenge results do not match combined source message and m value.");
                }
            }
        }
        catch (TranscriptVerificationException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new TranscriptVerificationException("Exception validating decryption challenge transcript: " + e.getMessage(), e);
        }
    }

    private boolean isSameParameters(ECDomainParameters a, ECDomainParameters b)
    {
        return a.getCurve().equals(b.getCurve()) && a.getG().equals(b.getG()) && a.getH().equals(b.getH()) && a.getN().equals(b.getN());
    }

    private void addPeer(int sequenceNo, ECPublicKeyParameters peerKey)
    {
        if ((sequenceNo + 1) > activePeers.length)
        {
            ECPublicKeyParameters[] tmp = new ECPublicKeyParameters[sequenceNo + 1];
            System.arraycopy(activePeers, 0, tmp, 0, activePeers.length);
            activePeers = tmp;
            maxSequenceNo = sequenceNo;
        }

        activePeers[sequenceNo] = peerKey;
    }
}
