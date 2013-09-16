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

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.crypto.Commitment;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.ECFixedTransform;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.ec.ECPairFactorTransform;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.cryptoworkshop.ximix.common.asn1.board.PairSequence;
import org.cryptoworkshop.ximix.common.asn1.message.MessageCommitment;
import org.cryptoworkshop.ximix.common.asn1.message.PostedData;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessage;
import org.cryptoworkshop.ximix.common.crypto.IndexCommitter;

/**
 * Verifier for the RPC style MixNet transcript that Ximix produces.
 * <p>
 * This verifier verifies that the shuffle process took place as advertised by verifying the encrypted results
 * for the revealed values and by
 * </p>
 */
public class ECShuffledTranscriptVerifier
{
    private final Map<Integer, PostedMessage> finalMap = new HashMap<>();
    private final Map<Integer, MessageCommitment> witnesses = new HashMap<>();
    private final Map<Integer, PostedMessage> initialMap = new HashMap<>();
    private final IndexCommitter commitChecker = new IndexCommitter(new SHA256Digest());
    private final Set<Integer> finalIndexesOfInterest = new HashSet<>();
    private final ECPublicKeyParameters pubKey;
    private ECCurve ecCurve;

    public ECShuffledTranscriptVerifier(ECPublicKeyParameters pubKey, InputStream witnessTranscript, InputStream initialTranscript, InputStream finalTranscript)
        throws IOException
    {
        this.pubKey = pubKey;
        this.ecCurve = pubKey.getParameters().getCurve();

        ASN1Primitive obj;

        try
        {
            //
            // we read the witnesses first as there is no need to load messages from the others if they
            // are not referenced here.
            //
            ASN1InputStream aIn = new ASN1InputStream(witnessTranscript);
            while ((obj = aIn.readObject()) != null)
            {
                PostedData pM = PostedData.getInstance(obj);
                MessageCommitment cm = MessageCommitment.getInstance(pM.getData());

                witnesses.put(pM.getIndex(), cm);
                finalIndexesOfInterest.add(cm.getNewIndex());
            }

            aIn = new ASN1InputStream(initialTranscript);

            while ((obj = aIn.readObject()) != null)
            {
                PostedMessage pM = PostedMessage.getInstance(obj);

                if (witnesses.containsKey(pM.getIndex()))
                {
                    initialMap.put(pM.getIndex(), pM);
                }
            }

            aIn = new ASN1InputStream(finalTranscript);

            while ((obj = aIn.readObject()) != null)
            {
                PostedMessage pM = PostedMessage.getInstance(obj);

                if (finalIndexesOfInterest.contains(pM.getIndex()))
                {
                    finalMap.put(pM.getIndex(), pM);
                    finalIndexesOfInterest.remove(pM.getIndex());
                }
            }
        }
        catch (IOException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new IOException("Unable to parse transcripts: " + e.getMessage(), e);
        }
    }

    /**
     * Verify that the transcripts are valid, throwing an exception if an issue is found.
     *
     * @throws TranscriptVerificationException
     */
    public void verify()
        throws TranscriptVerificationException
    {
        if (initialMap.size() != witnesses.size())
        {
            throw new TranscriptVerificationException("Initial transcript incomplete " + (witnesses.size() - initialMap.size()) + " messages missing.");
        }

        if (!finalIndexesOfInterest.isEmpty())
        {
            throw new TranscriptVerificationException("Final transcript incomplete " + finalIndexesOfInterest.size() + " messages missing.");
        }

        try
        {
            for (Integer msgIndex : witnesses.keySet())
            {
                PostedMessage initMsg = initialMap.get(msgIndex);
                MessageCommitment comMsg = witnesses.get(msgIndex);

                BigInteger kValue = new BigInteger(1, comMsg.getDetail());
                ECPairFactorTransform transform = new ECFixedTransform(kValue);

                transform.init(pubKey);

                PairSequence ecSeq = PairSequence.getInstance(ecCurve, initMsg.getMessage());
                ECPair[] ecInit = ecSeq.getECPairs();
                ECPair[] ecRes = new ECPair[ecSeq.size()];

                for (int i = 0; i != ecRes.length; i++)
                {
                    ecRes[i] = transform.transform(ecInit[i]);
                }

                PostedMessage finalMsg = finalMap.get(comMsg.getNewIndex());
                Commitment commitment = new Commitment(comMsg.getSecret(), finalMsg.getCommitment());

                if (commitChecker.isRevealed(commitment, comMsg.getNewIndex()))
                {
                    ECPair[] ecFin = PairSequence.getInstance(pubKey.getParameters().getCurve(), finalMsg.getMessage()).getECPairs();

                    if (!Arrays.equals(ecFin, ecRes))
                    {
                        throw new TranscriptVerificationException("Transformed cipher text does not match for relationship " + initMsg.getIndex() + " -> " + comMsg.getNewIndex());
                    }
                }
                else
                {
                    throw new TranscriptVerificationException("Commitment check failed for relationship " + initMsg.getIndex() + " -> " + comMsg.getNewIndex());
                }
            }
        }
        catch (TranscriptVerificationException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new TranscriptVerificationException("Exception validating transcripts: " + e.getMessage(), e);
        }
    }
}
