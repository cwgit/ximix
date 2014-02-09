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
package org.cryptoworkshop.ximix.node.crypto.service;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.cryptoworkshop.ximix.client.verify.CommitmentVerificationException;
import org.cryptoworkshop.ximix.client.verify.ECShuffledTranscriptVerifier;
import org.cryptoworkshop.ximix.client.verify.LinkIndexVerifier;
import org.cryptoworkshop.ximix.client.verify.SignedDataVerifier;
import org.cryptoworkshop.ximix.client.verify.TranscriptVerificationException;
import org.cryptoworkshop.ximix.common.asn1.board.PairSequence;
import org.cryptoworkshop.ximix.common.asn1.board.PairSequenceWithProofs;
import org.cryptoworkshop.ximix.common.asn1.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ClientMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CommandMessage;
import org.cryptoworkshop.ximix.common.asn1.message.DecryptShuffledBoardMessage;
import org.cryptoworkshop.ximix.common.asn1.message.DownloadShuffledBoardMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ErrorMessage;
import org.cryptoworkshop.ximix.common.asn1.message.FetchPublicKeyMessage;
import org.cryptoworkshop.ximix.common.asn1.message.FileTransferMessage;
import org.cryptoworkshop.ximix.common.asn1.message.Message;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessage;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessageDataBlock;
import org.cryptoworkshop.ximix.common.asn1.message.SeedAndWitnessMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ShareMessage;
import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.config.ConfigException;
import org.cryptoworkshop.ximix.common.util.EventNotifier;
import org.cryptoworkshop.ximix.node.crypto.operator.ECPrivateKeyOperator;
import org.cryptoworkshop.ximix.node.service.BasicNodeService;
import org.cryptoworkshop.ximix.node.service.NodeContext;
import org.cryptoworkshop.ximix.node.service.PrivateKeyOperator;

/**
 * Service class for perform decryption operations on the output of a shuffled board.
 */
public class NodeShuffledBoardDecryptionService
    extends BasicNodeService
{
    private final File workDirectory;
    private final SignedDataVerifier signatureVerifier;

    private Map<File, OutputStream> activeFiles = Collections.synchronizedMap(new HashMap<File, OutputStream>());
    private Map<String, ASN1InputStream> activeDecrypts = Collections.synchronizedMap(new HashMap<String, ASN1InputStream>());

    /**
     * Base constructor.
     *
     * @param nodeContext the context for the node we are in.
     * @param config source of config information if required.
     */
    public NodeShuffledBoardDecryptionService(NodeContext nodeContext, Config config)
        throws ConfigException
    {
        super(nodeContext);

        this.workDirectory = new File(nodeContext.getHomeDirectory(), "work");

        if (!this.workDirectory.exists())
        {
            if (!this.workDirectory.mkdir())
            {
                throw new ConfigException("Unable to create work directory: " + workDirectory.getPath());
            }
        }

        signatureVerifier = new SignedDataVerifier(nodeContext.getTrustAnchor());
    }

    public CapabilityMessage getCapability()
    {
        return new CapabilityMessage(CapabilityMessage.Type.SHUFFLE_DECRYPTION, new ASN1Encodable[0]); // TODO:
    }

    public MessageReply handle(Message message)
    {
        switch (((CommandMessage)message).getType())
        {
        case FILE_UPLOAD:
            FileTransferMessage transMessage = FileTransferMessage.getInstance(message.getPayload());
            File destinationFile = new File(workDirectory, transMessage.getFileName());

            try
            {
                OutputStream fileStream = activeFiles.get(destinationFile);
                if (fileStream == null)
                {
                    fileStream = new BufferedOutputStream(new FileOutputStream(destinationFile));

                    activeFiles.put(destinationFile, fileStream);
                }

                if (transMessage.isEndOfTransfer())
                {
                    fileStream.close();

                    activeFiles.remove(destinationFile);
                }
                else
                {
                    fileStream.write(transMessage.getChunk());
                }
            }
            catch (IOException e)
            {
                return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String(transMessage.getFileName() + ": " + e.getMessage()));
            }
            return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(transMessage.getFileName()));
        case SETUP_PARTIAL_DECRYPT:
            final DecryptShuffledBoardMessage setupMessage = DecryptShuffledBoardMessage.getInstance(message.getPayload());

            SubjectPublicKeyInfo keyInfo = nodeContext.getPublicKey(setupMessage.getKeyID());
            ECPublicKeyParameters pubKey;

            try
            {
                if (keyInfo != null)
                {
                    pubKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(keyInfo);
                }
                else
                {
                    // see if the key exists elsewhere on the MIXNET.
                    FetchPublicKeyMessage fetchMessage = new FetchPublicKeyMessage(setupMessage.getKeyID());

                    MessageReply reply = nodeContext.getPeerMap().values().iterator().next().sendMessage(ClientMessage.Type.FETCH_PUBLIC_KEY, fetchMessage);

                    if (reply.getPayload() != null)
                    {
                        pubKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(reply.getPayload().toASN1Primitive().getEncoded());
                    }
                    else
                    {
                        nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Unable to find public key " + setupMessage.getKeyID());

                        return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Unable to locate key " + setupMessage.getKeyID()));
                    }
                }
            }
            catch (Exception e)
            {
                nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Unable to process data for key " + setupMessage.getKeyID());

                return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Unable to process data for key " + setupMessage.getKeyID()));
            }


            // verify signatures.
            File[] files = workDirectory.listFiles(new FilenameFilter()
            {
                @Override
                public boolean accept(File dir, String name)
                {
                    return name.startsWith(setupMessage.getBoardName()) && name.endsWith(".gtr");
                }
            });

            final Map<Integer, File> generalTranscripts = createTranscriptMap(signatureVerifier, files);

            int boardSize;

            try
            {
                boardSize = LinkIndexVerifier.getAndCheckBoardSize(files);
            }
            catch (TranscriptVerificationException e)
            {
                nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Decrypt refused, size validation failed: " + e.getMessage(), e);

                return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Decrypt refused, size validation failed: " + e.getMessage()));
            }

            files = workDirectory.listFiles(new FilenameFilter()
            {
                @Override
                public boolean accept(File dir, String name)
                {
                    return name.startsWith(setupMessage.getBoardName()) && name.endsWith(".wtr");
                }
            });

            final Map<Integer, File> witnessTranscripts = createTranscriptMap(signatureVerifier, files);

            files = workDirectory.listFiles(new FilenameFilter()
            {
                @Override
                public boolean accept(File dir, String name)
                {
                    return name.startsWith(setupMessage.getBoardName()) && name.endsWith(".sc");
                }
            });

            final Map<String, byte[]> seedCommitmentMap = createSeedCommitmentMap(signatureVerifier, files);

            files = workDirectory.listFiles(new FilenameFilter()
            {
                @Override
                public boolean accept(File dir, String name)
                {
                    return name.startsWith(setupMessage.getBoardName()) && name.endsWith(".svw");
                }
            });

            final Map<String, byte[][]> seedAndWitnessesMap = createSeedAndWitnessMap(files);

            LinkIndexVerifier.Builder verifierBuilder = new LinkIndexVerifier.Builder(boardSize);

            try
            {
                verifierBuilder.setNetworkSeeds(seedCommitmentMap, seedAndWitnessesMap);

                for (Integer key : generalTranscripts.keySet())
                {
                    BufferedInputStream bIn = new BufferedInputStream(new FileInputStream(generalTranscripts.get(key)));

                    verifierBuilder.addTranscript(bIn);

                    bIn.close();
                }

                LinkIndexVerifier linkIndexVerifier = verifierBuilder.build();

                // verify which links have been opened.
                for (Integer key : witnessTranscripts.keySet())
                {
                    BufferedInputStream bIn = new BufferedInputStream(new FileInputStream(witnessTranscripts.get(key)));

                    linkIndexVerifier.verify(key, setupMessage.isWithPairing(), bIn);

                    bIn.close();
                }

                // verify the opened commitments.
                for (Integer key : witnessTranscripts.keySet())
                {
                    File transcriptFile = witnessTranscripts.get(key);
                    File initialTranscript = generalTranscripts.get(key);
                    File nextTranscript = generalTranscripts.get(key + 1);

                    InputStream witnessTranscriptStream = new BufferedInputStream(new FileInputStream(transcriptFile));
                    InputStream initialTranscriptStream = new BufferedInputStream(new FileInputStream(initialTranscript));
                    InputStream nextTranscriptStream = new BufferedInputStream(new FileInputStream(nextTranscript));

                    ECShuffledTranscriptVerifier verifier = new ECShuffledTranscriptVerifier(pubKey, witnessTranscriptStream, initialTranscriptStream, nextTranscriptStream);

                    verifier.verify();

                    witnessTranscriptStream.close();
                    initialTranscriptStream.close();
                    nextTranscriptStream.close();
                }
            }
            catch (CommitmentVerificationException e)
            {
                nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Decrypt refused, validation failed: " + e.getMessage(), e);

                return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Decrypt refused, validation failed: " + e.getMessage()));
            }
            catch (TranscriptVerificationException e)
            {
                nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Decrypt refused, validation failed: " + e.getMessage(), e);

                return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Decrypt refused, validation failed: " + e.getMessage()));
            }
            catch (Exception e)
            {
                nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, setupMessage.getBoardName() + ": " + e.getMessage(), e);

                return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String(setupMessage.getBoardName() + ": " + e.getMessage()));
            }

            File finalFile = generalTranscripts.get(witnessTranscripts.size());

            try
            {
                CMSSignedDataParser cmsParser = new CMSSignedDataParser(new BcDigestCalculatorProvider(), new BufferedInputStream(new FileInputStream(finalFile)));

                activeDecrypts.put(setupMessage.getBoardName(), new ASN1InputStream(cmsParser.getSignedContent().getContentStream()));

                return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(setupMessage.getBoardName()));
            }
            catch (Exception e)
            {
                nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Unable to process data for download key " + setupMessage.getKeyID());

                return new MessageReply(MessageReply.Type.ERROR, new ErrorMessage("Error opening posted message stream"));
            }
        case DOWNLOAD_PARTIAL_DECRYPTS:
            DownloadShuffledBoardMessage downMessage = DownloadShuffledBoardMessage.getInstance(message.getPayload());

            PostedMessageDataBlock.Builder  partialDecryptsBuilder = new PostedMessageDataBlock.Builder(downMessage.getBlockSize());

            PrivateKeyOperator operator = nodeContext.getPrivateKeyOperator(downMessage.getKeyID());

            if (!(operator instanceof ECPrivateKeyOperator))
            {
                return new MessageReply(MessageReply.Type.ERROR, new ErrorMessage("Inappropriate key type"));
            }

            ECPrivateKeyOperator ecOperator = (ECPrivateKeyOperator)operator;

            ECDomainParameters domainParameters = ecOperator.getDomainParameters();

            ASN1InputStream aIn = activeDecrypts.get(downMessage.getBoardName());

            if (aIn == null)
            {
                return new MessageReply(MessageReply.Type.OKAY, new ShareMessage(operator.getSequenceNo(), partialDecryptsBuilder.build()));
            }

            try
            {
                /*
                //
                // compute proof hash
                //
                SHA256Digest sha256 = new SHA256Digest();
                Map<String, SubjectPublicKeyInfo> keyInfoMap = new HashMap<>();

                //
                // compute the multiplier m
                //
                for (int i = 0; i != sourceMessage.length; i++)
                {
                    byte[] encoded = sourceMessage[i].getEncoded();

                    sha256.update(encoded, 0, encoded.length);
                }

                for (String node : nodes)
                {
                    AsymmetricKeyParameter key = keyMap.get(node);

                    SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key);

                    keyInfoMap.put(node, keyInfo);

                    byte[] encoded = keyInfo.getEncoded();

                    sha256.update(encoded, 0, encoded.length);
                }

                byte[] mEnc = new byte[sha256.getDigestSize()];

                sha256.doFinal(mEnc, 0);

                BigInteger m = new BigInteger(1, mEnc);

                ECPoint[] challengeMessage = new ECPoint[sourceMessage.length];

                for (int i = 0; i != sourceMessage.length; i++)
                {
                    challengeMessage[i] = sourceMessage[i].multiply(m);
                }
                  */

                Object o = null;
                ProofGenerator pGen = new ProofGenerator();
                while (partialDecryptsBuilder.hasCapacity() && (o = aIn.readObject()) != null)
                {
                    PostedMessage postedMessage = PostedMessage.getInstance(o);
                    PairSequence ps = PairSequence.getInstance(domainParameters.getCurve(), postedMessage.getMessage());
                    ECPair[] pairs = ps.getECPairs();
                    ECPoint[] proofs = new ECPoint[pairs.length];

                    for (int j = 0; j != pairs.length; j++)
                    {
                        pairs[j] = new ECPair(ecOperator.transform(pairs[j].getX()), pairs[j].getY());
                    }

                    BigInteger challenge = pGen.computeChallenge(ps.getECPairs(), pairs);

                    for (int j = 0; j != pairs.length; j++)
                    {
                        proofs[j] = pGen.computeProof(pairs[j].getX(), challenge, domainParameters, ecOperator);
                    }

                    partialDecryptsBuilder.add(new PairSequenceWithProofs(pairs, proofs).getEncoded());
                }

                if (o == null)
                {
                    activeDecrypts.remove(downMessage.getBoardName());
                    aIn.close();
                }

                return new MessageReply(MessageReply.Type.OKAY, new ShareMessage(operator.getSequenceNo(), partialDecryptsBuilder.build()));
            }
            catch (Exception e)
            {
                nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Error parsing posted message stream: " + e.getMessage(), e);

                return new MessageReply(MessageReply.Type.ERROR, new ErrorMessage("Error parsing posted message stream: " + e.getMessage()));
            }
        default:
            nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Unknown command: " + message.getType());

            return new MessageReply(MessageReply.Type.ERROR, new ErrorMessage("Unknown command: " + message.getType()));
        }
    }

    public boolean isAbleToHandle(Message message)
    {
        return message.getType() == CommandMessage.Type.FILE_UPLOAD
            || message.getType() == CommandMessage.Type.SETUP_PARTIAL_DECRYPT
            || message.getType() == CommandMessage.Type.DOWNLOAD_PARTIAL_DECRYPTS;
    }

    private Map createTranscriptMap(SignedDataVerifier verifier, File[] fileList)
    {
        final Map<Integer, File> transcripts = new TreeMap<>();

        for (File file : fileList)
        {
            String name = file.getName();
            int beginIndex = name.indexOf('.') + 1;
            int stepNumber = Integer.parseInt(name.substring(beginIndex, name.indexOf('.', beginIndex)));

            try
            {
                CMSSignedDataParser cmsParser = new CMSSignedDataParser(new BcDigestCalculatorProvider(), new BufferedInputStream(new FileInputStream(file)));

                if (verifier.signatureVerified(cmsParser))
                {
                    transcripts.put(stepNumber, file);
                }
                else
                {
                    nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Signature check failed: " + file.getPath());
                }

                cmsParser.close();
            }
            catch (Exception e)
            {
                nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Signature check failed on  " + file.getPath() + ": " + e.getMessage(), e);
            }
        }

        return transcripts;
    }

    private Map<String, byte[][]> createSeedAndWitnessMap(File[] fileList)
    {
        final Map<String, byte[][]> transcripts = new TreeMap<>();

        for (File file : fileList)
        {
            String name = file.getName();
            int beginIndex = name.indexOf('.') + 1;
            String nodeName = name.substring(beginIndex, name.indexOf('.', beginIndex));

            try
            {
                ASN1InputStream aIn = new ASN1InputStream(new FileInputStream(file));

                SeedAndWitnessMessage sAnW = SeedAndWitnessMessage.getInstance(aIn.readObject());

                if (aIn.readObject() != null)
                {
                    nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "createSeedAndWitnessMap extra data found: " + file.getPath());
                }

                transcripts.put(nodeName, new byte[][] { sAnW.getSeed(), sAnW.getWitness() });

                aIn.close();
            }
            catch (Exception e)
            {
                nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Signature check failed on  " + file.getPath() + ": " + e.getMessage(), e);
            }
        }

        return transcripts;
    }

    private Map<String, byte[]> createSeedCommitmentMap(SignedDataVerifier verifier, File[] fileList)
    {
        final Map<String, byte[]> transcripts = new TreeMap<>();

        for (File file : fileList)
        {
            String name = file.getName();
            int beginIndex = name.indexOf('.') + 1;
            String nodeName = name.substring(beginIndex, name.indexOf('.', beginIndex));

            try
            {
                BufferedInputStream sigData = new BufferedInputStream(new FileInputStream(file));

                CMSSignedData cmsSignedData = new CMSSignedData(sigData);

                if (verifier.signatureVerified(cmsSignedData))
                {
                    transcripts.put(nodeName, cmsSignedData.getEncoded());
                }
                else
                {
                    nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Signature check failed: " + file.getPath());
                }

                sigData.close();
            }
            catch (Exception e)
            {
                nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Signature check failed on  " + file.getPath() + ": " + e.getMessage(), e);
            }
        }

        return transcripts;
    }
}
