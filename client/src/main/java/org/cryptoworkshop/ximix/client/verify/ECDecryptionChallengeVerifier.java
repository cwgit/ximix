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

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.cryptoworkshop.ximix.common.asn1.board.PairSequence;
import org.cryptoworkshop.ximix.common.asn1.board.PointSequence;
import org.cryptoworkshop.ximix.common.asn1.message.ChallengeLogMessage;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessage;
import org.cryptoworkshop.ximix.common.crypto.threshold.LagrangeWeightCalculator;

/**
 * Verifier for a decryption challenge log stream and stream of outputs.
 */
public class ECDecryptionChallengeVerifier
{
    private final ECPublicKeyParameters pubKey;
    private final InputStream logStream;
    private final InputStream resultStream;
    private final InputStream lastStageStream;

    private ECPublicKeyParameters[] activePeers = new ECPublicKeyParameters[0];
    private ECPoint[][] activeMsgParts = new ECPoint[0][];
    private int maxSequenceNo = 0;

    /**
     * Base constructor.
     *
     * @param pubKey the public key that we are verifying against.
     * @param lastStageStream InputStream representing the last shuffle stage.
     * @param resultStream InputStream representing the final out that was assembled.
     * @param logStream InputStream representing the decryption challenge transcript.
     */
    public ECDecryptionChallengeVerifier(ECPublicKeyParameters pubKey, InputStream lastStageStream, InputStream resultStream, InputStream logStream)
    {
        this.pubKey = pubKey;
        this.lastStageStream = lastStageStream;
        this.resultStream = resultStream;
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
        ASN1InputStream resultIn = new ASN1InputStream(resultStream);
        ASN1InputStream lastIn = new ASN1InputStream(lastStageStream);

        try
        {
            int messageIndex = -1;

            ASN1Object obj;
            while ((obj = aIn.readObject()) != null)
            {
                ChallengeLogMessage logMessage = ChallengeLogMessage.getInstance(obj);

                ECPoint[] sourceMessage = logMessage.getSourceMessage();
                ECPoint[] proofs = logMessage.getProofs();

                ECPublicKeyParameters currentPubKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(logMessage.getKeyInfo());
                if (!isSameParameters(pubKey.getParameters(), currentPubKey.getParameters()))
                {
                    throw new TranscriptVerificationException("Log message indicates inconsistent public key parameters.");
                }

                if (messageIndex != logMessage.getIndex())
                {
                    if (activePeers.length != 0)
                    {
                        LagrangeWeightCalculator weightCalculator = new LagrangeWeightCalculator(maxSequenceNo + 1, pubKey.getParameters().getN());

                        ECPoint accumulatedQ = null;

                        BigInteger[] weights = weightCalculator.computeWeights(activePeers);

                         // verify the partial public keys represent the one we have.
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

                        // verify the partial decrypts result in the final message
                        PostedMessage pM = PostedMessage.getInstance(lastIn.readObject());
                        ECPair[] encPairs = PairSequence.getInstance(pubKey.getParameters().getCurve(), pM.getMessage()).getECPairs();

                        int len = activeMsgParts[0].length;
                        for (int i = 1; i != activeMsgParts.length; i++)
                        {
                             if (activeMsgParts[i].length != len)
                             {
                                 throw new TranscriptVerificationException("Partial decrypt length mismatch");
                             }
                        }

                        int baseIndex = 0;
                        for (int i = 0; i != activeMsgParts.length; i++)
                        {
                            if (activeMsgParts[i] != null)
                            {
                                baseIndex = i;
                                break;
                            }
                        }

                        BigInteger baseWeight = weights[baseIndex];

                        ECPoint[] decryptions = reassemblePoints(activeMsgParts, encPairs, weights, baseIndex, baseWeight);

                        ECPoint[] recordedDecrypts = PointSequence.getInstance(pubKey.getParameters().getCurve(), resultIn.readObject()).getECPoints();

                        if (!Arrays.areEqual(decryptions, recordedDecrypts))
                        {
                            throw new TranscriptVerificationException("Recorded decrypts do not match partial ones.");
                        }

                        // reset the peers array.
                        for (int i = 0; i != activePeers.length; i++)
                        {
                            activePeers[i] = null;
                        }
                        for (int i = 0; i != activeMsgParts.length; i++)
                        {
                            activeMsgParts[i] = null;
                        }
                    }
                    else if (messageIndex != -1)
                    {
                        throw new TranscriptVerificationException("Nothing to verify!");
                    }

                    messageIndex = logMessage.getIndex();
                }

                addPeer(logMessage.getSequenceNo(), currentPubKey, logMessage.getSourceMessage());

                if (!logMessage.hasPassed())
                {
                    throw new TranscriptVerificationException("Log message indicates challenge did not pass.");
                }

                for (int i = 0; i != sourceMessage.length; i++)
                {
                    // check proof
                    if (!sourceMessage[i].add(activePeers[logMessage.getSequenceNo()].getQ().multiply(logMessage.getM())).normalize().equals(proofs[i]))
                    {
                        throw new TranscriptVerificationException("Proof results do not match combined source message and m value.");
                    }
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

    private void addPeer(int sequenceNo, ECPublicKeyParameters peerKey, ECPoint[] peerMsgPart)
    {
        if ((sequenceNo + 1) > activePeers.length)
        {
            ECPublicKeyParameters[] tmp = new ECPublicKeyParameters[sequenceNo + 1];
            System.arraycopy(activePeers, 0, tmp, 0, activePeers.length);
            activePeers = tmp;

            ECPoint[][] tmpEC = new ECPoint[sequenceNo + 1][];
            System.arraycopy(activeMsgParts, 0, tmpEC, 0, activeMsgParts.length);
            activeMsgParts = tmpEC;

            maxSequenceNo = sequenceNo;
        }

        activePeers[sequenceNo] = peerKey;
        activeMsgParts[sequenceNo] = peerMsgPart;
    }

    private ECPoint[] reassemblePoints(ECPoint[][] partialDecrypts, ECPair[] encMessage, BigInteger[] weights, int baseIndex, BigInteger baseWeight)
    {
        ECPoint[] weightedDecryptions = new ECPoint[partialDecrypts[0].length];
        ECPoint[] fulls = new ECPoint[partialDecrypts[0].length];

        ECPair[] partials = new ECPair[partialDecrypts[baseIndex].length];

        for (int i = 0; i != partials.length; i++)
        {
            partials[i] = new ECPair(partialDecrypts[baseIndex][i], encMessage[i].getY());
        }

        for (int i = 0; i != weightedDecryptions.length; i++)
        {
            weightedDecryptions[i] = partials[i].getX().multiply(baseWeight);
        }

        for (int wIndex = baseIndex + 1; wIndex < weights.length; wIndex++)
        {
            if (weights[wIndex] != null)
            {
                for (int i = 0; i != weightedDecryptions.length; i++)
                {
                    weightedDecryptions[i] = weightedDecryptions[i].add(partialDecrypts[wIndex][i].multiply(weights[wIndex]));
                }
            }
        }

        for (int i = 0; i != weightedDecryptions.length; i++)
        {
            fulls[i] = partials[i].getY().add(weightedDecryptions[i].negate());
        }

        return fulls;
    }
}
