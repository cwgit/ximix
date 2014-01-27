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
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.crypto.Commitment;
import org.bouncycastle.crypto.Committer;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.commitments.GeneralHashCommitter;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.cryptoworkshop.ximix.common.asn1.message.MessageCommitment;
import org.cryptoworkshop.ximix.common.asn1.message.PostedData;
import org.cryptoworkshop.ximix.common.asn1.message.SeedCommitmentMessage;
import org.cryptoworkshop.ximix.common.util.challenge.SeededChallenger;

/**
 * Verifier for link index challenges. If the challenge seed produced by the verifier is use in the network
 * the indexes of the witnesses sent back should correspond to the number generation used here.
 */
public class LinkIndexVerifier
{
    public static class Builder
    {
        private final int boardSize;

        private Digest transcriptDigest = new SHA512Digest();
        private byte[] remoteSeed;

        public Builder(int boardSize)
        {
            this.boardSize = boardSize;
        }

        public Builder addTranscript(InputStream transcriptStream)
            throws IOException
        {
            byte[] buf = new byte[1024];

            int len;
            while ((len = transcriptStream.read(buf)) >= 0)
            {
               transcriptDigest.update(buf, 0, len);
            }

            return this;
        }

        public Builder addTranscript(File transcriptFile)
            throws IOException
        {
            return this.addTranscript(new FileInputStream(transcriptFile));
        }

        public Builder setNetworkSeeds(Map<String, byte[]> seedCommitmentMap, Map<String, byte[][]> seedAndWitnessesMap)
            throws CommitmentVerificationException
        {
            Committer sha512Committer = new GeneralHashCommitter(new SHA512Digest(), null);

            for (String node : seedCommitmentMap.keySet())
            {
                byte[][] seedAndWitness = seedAndWitnessesMap.get(node);

                CMSSignedData signedData;

                try
                {
                    signedData = new CMSSignedData(seedCommitmentMap.get(node));
                }
                catch (CMSException e)
                {
                    throw new CommitmentVerificationException("Cannot parse commitment data for seed " + node + ":" + e.getMessage(), e);
                }

                SeedCommitmentMessage seedCommitmentMessage = SeedCommitmentMessage.getInstance(signedData.getSignedContent().getContent());

                Commitment commitment = new Commitment(seedAndWitness[1], seedCommitmentMessage.getCommitment());

                if (!sha512Committer.isRevealed(commitment, seedAndWitness[0]))
                {
                    throw new CommitmentVerificationException("Commitment check failed on seed");
                }

                if (remoteSeed == null)
                {
                    remoteSeed = seedAndWitness[0].clone();
                }
                else
                {
                    byte[] nSeed = seedAndWitness[0];

                    for (int i = 0; i != remoteSeed.length; i++)
                    {
                        remoteSeed[i] ^= nSeed[i];
                    }
                }
            }

            return this;
        }

        public LinkIndexVerifier build()
        {
            transcriptDigest.update(remoteSeed, 0, remoteSeed.length);

            byte[] challengeSeed = new byte[transcriptDigest.getDigestSize()];

            transcriptDigest.doFinal(challengeSeed, 0);

            return new LinkIndexVerifier(boardSize, challengeSeed);
        }
    }

    private final int boardSize;
    private final byte[] challengeSeed;

    private SignerId lastSID;
    private Set<Integer> nextIndexes = new HashSet<>();

    private LinkIndexVerifier(int boardSize, byte[] challengeSeed)
    {
        this.boardSize = boardSize;
        this.challengeSeed = challengeSeed;
    }

    public byte[] getChallengeSeed()
    {
        return challengeSeed;
    }

    public void verify(int stepNo, boolean isWithPairing, InputStream transcript)
        throws TranscriptVerificationException
    {
        CMSSignedDataParser cmsParser;
        SignerId currentSID;
        Set<Integer> pmIndexes = new HashSet<>();
        Set<Integer> cmIndexes = new HashSet<>();

        try
        {
            cmsParser = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(), transcript);

            ASN1InputStream aIn = new ASN1InputStream(cmsParser.getSignedContent().getContentStream());
            Object obj;
            while ((obj = aIn.readObject()) != null)
            {
                PostedData pM = PostedData.getInstance(obj);
                MessageCommitment cm = MessageCommitment.getInstance(pM.getData());

                pmIndexes.add(pM.getIndex());
                cmIndexes.add(cm.getNewIndex());
            }

            currentSID = ((SignerInformation)cmsParser.getSignerInfos().getSigners().iterator().next()).getSID();
        }
        catch (Exception e)
        {
            throw new TranscriptVerificationException("Cannot parse CMS wrapper on transcript: " + e.getMessage(), e);
        }

        SHA512Digest seedDigest = new SHA512Digest();
        byte[]       stepSeed = new byte[seedDigest.getDigestSize()];

        // we follow the formulation in "Randomized Partial Checking Revisited" where the seed is
        // modified by the step number, the one difference being that in our case this will only take
        // place at the start of a pairing, or on an individual step.
        seedDigest.update(this.challengeSeed, 0, this.challengeSeed.length);

        seedDigest.update((byte)(stepNo >>> 24));
        seedDigest.update((byte)(stepNo >>> 16));
        seedDigest.update((byte)(stepNo >>> 8));
        seedDigest.update((byte)stepNo);

        seedDigest.doFinal(stepSeed, 0);

        SeededChallenger seedChallenger = new SeededChallenger(boardSize, stepNo, stepSeed);
        Set<Integer> indexes = new HashSet<>();

        while (seedChallenger.hasNext())
        {
            indexes.add(seedChallenger.nextIndex());
        }

        if (isWithPairing)
        {
            if (!currentSID.equals(lastSID))
            {
                for (int i = 0; i != boardSize; i++)
                {
                    nextIndexes.add(i);
                }
            }
            else
            {
                indexes = new HashSet<>(nextIndexes);
            }
        }

        lastSID = currentSID;

        if (indexes.size() != pmIndexes.size())
        {
             throw new TranscriptVerificationException("Entries in witness table do not correspond to seeding - step " + stepNo + " size( " + indexes.size() + ", " + pmIndexes.size() + ")");
        }

        indexes.removeAll(pmIndexes);
        nextIndexes.removeAll(cmIndexes);

        if (!indexes.isEmpty())
        {
             throw new TranscriptVerificationException("Entries in witness table do not correspond to seeding - step " + stepNo + " unaccounted " + indexes.size());
        }
    }

    /**
     * Return the number of messages that were on the board producing these commitments.
     *
     * @param fileList list of general transcript files.
     * @return number of messages on the board.
     * @throws TranscriptVerificationException if there is a mismatch in the file size.
     */
    public static int getAndCheckBoardSize(File[] fileList)
        throws TranscriptVerificationException
    {
        int   boardSize = -1;

        for (File file : fileList)
        {
            int count = 0;

            try
            {
                CMSSignedDataParser cmsParser = new CMSSignedDataParser(new BcDigestCalculatorProvider(), new BufferedInputStream(new FileInputStream(file)));

                ASN1InputStream aIn = new ASN1InputStream(cmsParser.getSignedContent().getContentStream());

                while (aIn.readObject() != null)
                {
                    count++;
                }

                if (boardSize == -1)
                {
                    boardSize = count;
                }
                else if (count != boardSize)
                {
                    throw new TranscriptVerificationException("Size mismatch in commitment files: " + file.getPath());
                }

                cmsParser.close();
            }
            catch (Exception e)
            {
                throw new TranscriptVerificationException("Size check failed on  " + file.getPath() + ": " + e.getMessage(), e);
            }
        }

        return boardSize;
    }
}
