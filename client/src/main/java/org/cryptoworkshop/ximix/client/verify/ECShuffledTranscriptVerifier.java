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

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
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
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.crypto.Commitment;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.ECFixedTransform;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.ec.ECPairFactorTransform;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
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
    private final ASN1InputStream witnessTranscript;
    private final Object initialTranscript;
    private final Object finalTranscript;
    private final Map<Integer, PostedMessage> finalMap = new HashMap<>();
    private final Map<Integer, MessageCommitment> witnesses = new HashMap<>();
    private final Map<Integer, PostedMessage> initialMap = new HashMap<>();
    private final IndexCommitter commitChecker = new IndexCommitter(new SHA256Digest());
    private final Set<Integer> finalIndexesOfInterest = new HashSet<>();
    private final ECPublicKeyParameters pubKey;
    private ECCurve ecCurve;

    /**
     * Base Constructor.
     *
     * @param pubKey the public key we are verifying against.
     * @param witnessTranscript transcript of witness values.
     * @param initialTranscript transcript of shuffle input.
     * @param finalTranscript transcript of shuffle output.
     * @throws IOException if any of the transcripts cannot be successfully parsed.
     */
    public ECShuffledTranscriptVerifier(ECPublicKeyParameters pubKey, InputStream witnessTranscript, InputStream initialTranscript, InputStream finalTranscript)
        throws IOException
    {
        this.pubKey = pubKey;
        this.ecCurve = pubKey.getParameters().getCurve();

        try
        {
            //
            // we read the witnesses first as there is no need to load messages from the others if they
            // are not referenced here.
            //
            CMSSignedDataParser cmsParser = new CMSSignedDataParser(new BcDigestCalculatorProvider(), witnessTranscript);

            this.witnessTranscript = new ASN1InputStream(cmsParser.getSignedContent().getContentStream());
            this.initialTranscript = initialTranscript;
            this.finalTranscript = finalTranscript;
        }
        catch (Exception e)
        {
            throw new IOException("Unable to parse transcripts: " + e.getMessage(), e);
        }
    }

    /**
     * File based constructor - this will process the witnessTranscript in batches.
     *
     * @param pubKey the public key we are verifying against.
     * @param witnessTranscriptStream transcript of witness values.
     * @param initialTranscript transcript of shuffle input.
     * @param finalTranscript transcript of shuffle output.
     * @throws IOException if any of the transcripts cannot be successfully parsed.
     */
    public ECShuffledTranscriptVerifier(ECPublicKeyParameters pubKey, InputStream witnessTranscriptStream, File initialTranscript, File finalTranscript)
        throws IOException
    {
        this.pubKey = pubKey;
        this.ecCurve = pubKey.getParameters().getCurve();

        try
        {
            //
            // we read the witnesses first as there is no need to load messages from the others if they
            // are not referenced here.
            //
            CMSSignedDataParser cmsParser = new CMSSignedDataParser(new BcDigestCalculatorProvider(), witnessTranscriptStream);

            this.witnessTranscript = new ASN1InputStream(cmsParser.getSignedContent().getContentStream());
            this.initialTranscript = initialTranscript;
            this.finalTranscript = finalTranscript;
        }
        catch (Exception e)
        {
            throw new IOException("Unable to parse transcripts: " + e.getMessage(), e);
        }
    }

    private boolean loadWitnesses(ASN1InputStream transcript, int maxCount)
        throws TranscriptVerificationException
    {
        try
        {
            ASN1Primitive obj = null;

            if (maxCount < 0)
            {
                while ((obj = transcript.readObject()) != null)
                {
                    PostedData pM = PostedData.getInstance(obj);
                    MessageCommitment cm = MessageCommitment.getInstance(pM.getData());

                    witnesses.put(pM.getIndex(), cm);
                    finalIndexesOfInterest.add(cm.getNewIndex());
                }
            }
            else
            {
                int count = 0;

                while ((count < maxCount) && (obj = transcript.readObject()) != null)
                {
                    PostedData pM = PostedData.getInstance(obj);
                    MessageCommitment cm = MessageCommitment.getInstance(pM.getData());

                    witnesses.put(pM.getIndex(), cm);
                    finalIndexesOfInterest.add(cm.getNewIndex());
                    count++;
                }
            }

            return (obj != null);
        }
        catch (Exception e)
        {
            throw new TranscriptVerificationException("Exception validating transcripts: " + e.getMessage(), e);
        }
    }

    private void loadCommitments(InputStream initialTranscript, InputStream finalTranscript)
        throws TranscriptVerificationException
    {
        try
        {
            CMSSignedDataParser cmsParser = new CMSSignedDataParser(new BcDigestCalculatorProvider(), initialTranscript);
            ASN1InputStream aIn = new ASN1InputStream(cmsParser.getSignedContent().getContentStream());
            ASN1Primitive obj;

            while ((obj = aIn.readObject()) != null)
            {
                PostedMessage pM = PostedMessage.getInstance(obj);

                if (witnesses.containsKey(pM.getIndex()))
                {
                    initialMap.put(pM.getIndex(), pM);
                }
            }

            cmsParser = new CMSSignedDataParser(new BcDigestCalculatorProvider(), finalTranscript);
            aIn = new ASN1InputStream(cmsParser.getSignedContent().getContentStream());

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
        catch (Exception e)
        {
            throw new TranscriptVerificationException("Exception validating transcripts: " + e.getMessage(), e);
        }
    }

    /**
     * Verify that the transcripts are valid, throwing an exception if an issue is found.
     *
     * @throws TranscriptVerificationException on verification failure.
     */
    public void verify()
        throws TranscriptVerificationException
    {
        // if we've been past streams we have to read the lot in one go.
        int batchSize = (initialTranscript instanceof InputStream) ? -1 : 2000;     // TODO: make batch size configurable
        boolean moreWitnesses = true;

        while (moreWitnesses)
        {
            moreWitnesses = loadWitnesses(witnessTranscript, batchSize);

            if (witnesses.isEmpty())
            {
                break;
            }

            if (initialTranscript instanceof InputStream)
            {
                loadCommitments((InputStream)initialTranscript, (InputStream)finalTranscript);
            }
            else
            {
                try
                {
                    InputStream initTranscript = new BufferedInputStream(new FileInputStream((File)initialTranscript));
                    InputStream finTranscript = new BufferedInputStream(new FileInputStream((File)finalTranscript));

                    loadCommitments(initTranscript, finTranscript);

                    initTranscript.close();
                    finTranscript.close();
                }
                catch (IOException e)
                {
                    throw new TranscriptVerificationException("Exception validating transcripts: " + e.getMessage(), e);
                }
            }

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

            witnesses.clear();
            initialMap.clear();
            finalMap.clear();
            finalIndexesOfInterest.clear();
        }
    }
}
