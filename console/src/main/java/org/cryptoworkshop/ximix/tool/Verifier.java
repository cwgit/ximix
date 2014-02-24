package org.cryptoworkshop.ximix.tool;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.TreeMap;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.Arrays;
import org.cryptoworkshop.ximix.client.verify.CommitmentVerificationException;
import org.cryptoworkshop.ximix.client.verify.ECDecryptionChallengeVerifier;
import org.cryptoworkshop.ximix.client.verify.ECShuffledTranscriptVerifier;
import org.cryptoworkshop.ximix.client.verify.LinkIndexVerifier;
import org.cryptoworkshop.ximix.client.verify.SignedDataVerifier;
import org.cryptoworkshop.ximix.client.verify.TranscriptVerificationException;
import org.cryptoworkshop.ximix.common.asn1.board.PairSequence;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessage;
import org.cryptoworkshop.ximix.common.asn1.message.SeedAndWitnessMessage;

public class Verifier
{
    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        File trustAnchor = new File(args[0]);
        File publicKey = new File(args[1]);
        boolean paired = Boolean.valueOf(args[2]);
        File ballotDirectory = new File(args[3]);
        File workingDirectory = new File(args[4]);
        String region = args[5];
        String type = args[6];
        final String ballotName = region + "_" + type;

        CertificateFactory certFact = CertificateFactory.getInstance("X.509", "BC");

        SignedDataVerifier signatureVerifier = new SignedDataVerifier((X509Certificate)certFact.generateCertificate(new FileInputStream(trustAnchor)));

        PEMParser pemParser = new PEMParser(new FileReader(publicKey));

        SubjectPublicKeyInfo keyInfo = (SubjectPublicKeyInfo)pemParser.readObject();

        ECPublicKeyParameters pubKey;

        try
        {
            pubKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(keyInfo);
        }
        catch (Exception e)
        {
            throw new TranscriptVerificationException("Unable to process data for key " + publicKey);
        }


        // verify signatures.
        File[] files = workingDirectory.listFiles(new FilenameFilter()
        {
            @Override
            public boolean accept(File dir, String name)
            {
                return name.startsWith(ballotName) && name.endsWith(".gtr");
            }
        });

        final Map<Integer, File> generalTranscripts = createTranscriptMap(signatureVerifier, files);

        int boardSize = LinkIndexVerifier.getAndCheckBoardSize(files);

        files = workingDirectory.listFiles(new FilenameFilter()
        {
            @Override
            public boolean accept(File dir, String name)
            {
                return name.startsWith(ballotName) && name.endsWith(".wtr");
            }
        });

        final Map<Integer, File> witnessTranscripts = createTranscriptMap(signatureVerifier, files);

        files = workingDirectory.listFiles(new FilenameFilter()
        {
            @Override
            public boolean accept(File dir, String name)
            {
                return name.startsWith(ballotName) && name.endsWith(".sc");
            }
        });

        final Map<String, byte[]> seedCommitmentMap = createSeedCommitmentMap(signatureVerifier, files);

        files = workingDirectory.listFiles(new FilenameFilter()
        {
            @Override
            public boolean accept(File dir, String name)
            {
                return name.startsWith(ballotName) && name.endsWith(".svw");
            }
        });

        final Map<String, byte[][]> seedAndWitnessesMap = createSeedAndWitnessMap(files);

        System.out.print("Verifying ballot input: ");

        try
        {
            File firstFile = generalTranscripts.get(0);

            files = ballotDirectory.listFiles(new FilenameFilter()
            {
                @Override
                public boolean accept(File dir, String name)
                {
                    return name.startsWith(ballotName) && name.endsWith(".blt");
                }
            });

            CMSSignedDataParser cmsParser = new CMSSignedDataParser(new BcDigestCalculatorProvider(), new BufferedInputStream(new FileInputStream(firstFile)));

            ASN1InputStream initialBallots = new ASN1InputStream(new FileInputStream(files[0]));
            ASN1InputStream initialBoard = new ASN1InputStream(cmsParser.getSignedContent().getContentStream());

            ASN1Object obj;
            while ((obj = initialBallots.readObject()) != null)
            {
                PairSequence init = PairSequence.getInstance(pubKey.getParameters().getCurve(), obj);
                PairSequence board = PairSequence.getInstance(pubKey.getParameters().getCurve(), PostedMessage.getInstance(initialBoard.readObject()).getMessage());

                if (!Arrays.areEqual(init.getECPairs(), board.getECPairs()))
                {
                    throw new TranscriptVerificationException("Initial ballots and initial board do not match.");
                }
            }

            initialBallots.close();
            initialBoard.close();

            System.out.println(" Done.");
        }
        catch (Exception e)
        {
            throw new TranscriptVerificationException("Error opening posted message stream: " + e.getMessage(), e);
        }

        LinkIndexVerifier.Builder verifierBuilder = new LinkIndexVerifier.Builder(boardSize);

        try
        {
            System.out.print("Verifying correct order of link opening: ");

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

                linkIndexVerifier.verify(key, paired, bIn);

                bIn.close();

                System.out.print(".");
            }

            System.out.println(" Done.");

            System.out.print("Verifying opened links: ");

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

                System.out.print(".");
            }

            System.out.println(" Done.");
        }
        catch (CommitmentVerificationException e)
        {
            throw new TranscriptVerificationException("Decrypt refused, validation failed: " + e.getMessage());
        }
        catch (TranscriptVerificationException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new TranscriptVerificationException(ballotName + ": " + e.getMessage());
        }

        System.out.print("Verifying decryptions: ");

        try
        {
            File finalFile = generalTranscripts.get(witnessTranscripts.size());

            CMSSignedDataParser cmsParser = new CMSSignedDataParser(new BcDigestCalculatorProvider(), new BufferedInputStream(new FileInputStream(finalFile)));

            ECDecryptionChallengeVerifier verifier = new ECDecryptionChallengeVerifier(pubKey,
                                                           cmsParser.getSignedContent().getContentStream(),
                                                           new FileInputStream(new File(workingDirectory, ballotName + ".out")),
                                                           new FileInputStream(new File(workingDirectory, ballotName + ".plg")));

            verifier.verify();

            System.out.println(" Done.");
        }
        catch (Exception e)
        {
            throw new TranscriptVerificationException("Error opening posted message stream: " + e.getMessage(), e);
        }

        System.out.println("Ballot for " + region + " of type " + type + " verified.");
    }

    private static Map createTranscriptMap(SignedDataVerifier verifier, File[] fileList)
        throws TranscriptVerificationException
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
                    throw new TranscriptVerificationException("Signature check failed: " + file.getPath());
                }

                cmsParser.close();
            }
            catch (Exception e)
            {
                throw new TranscriptVerificationException("Signature check failed on  " + file.getPath() + ": " + e.getMessage(), e);
            }
        }

        return transcripts;
    }

    private static Map<String, byte[][]> createSeedAndWitnessMap(File[] fileList)
        throws TranscriptVerificationException
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
                    throw new TranscriptVerificationException("createSeedAndWitnessMap extra data found: " + file.getPath());
                }

                transcripts.put(nodeName, new byte[][]{sAnW.getSeed(), sAnW.getWitness()});

                aIn.close();
            }
            catch (Exception e)
            {
                throw new TranscriptVerificationException("Signature check failed on  " + file.getPath() + ": " + e.getMessage(), e);
            }
        }

        return transcripts;
    }

    private static Map<String, byte[]> createSeedCommitmentMap(SignedDataVerifier verifier, File[] fileList)
        throws TranscriptVerificationException
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
                    throw new TranscriptVerificationException("Signature check failed: " + file.getPath());
                }

                sigData.close();
            }
            catch (Exception e)
            {
                throw new TranscriptVerificationException("Signature check failed on  " + file.getPath() + ": " + e.getMessage(), e);
            }
        }

        return transcripts;
    }
}
