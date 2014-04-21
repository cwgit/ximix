package org.cryptoworkshop.ximix.tool;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
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
import org.cryptoworkshop.ximix.common.asn1.board.PointSequence;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessage;
import org.cryptoworkshop.ximix.common.asn1.message.SeedAndWitnessMessage;
import org.cryptoworkshop.ximix.console.util.vote.BallotUnpacker;
import org.json.JSONException;
import uk.ac.surrey.cs.tvs.utils.io.exceptions.JSONIOException;

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
        File mapProperties = new File(args[4]);
        File workingDirectory = new File(args[5]);
        String region = args[6];
        String type = args[7];
        String meta = args[8];
        final String ballotName = region + "_" + type + "_" + meta;

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

                ECShuffledTranscriptVerifier verifier = new ECShuffledTranscriptVerifier(pubKey, witnessTranscriptStream, initialTranscript, nextTranscript);

                verifier.verify();

                witnessTranscriptStream.close();

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
        catch (TranscriptVerificationException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new TranscriptVerificationException("Error opening posted message stream: " + e.getMessage(), e);
        }

        System.out.print("Verifying CSVs: ");

        try
        {
            CSVVerifier verifier = new CSVVerifier(mapProperties, new File(workingDirectory, ballotName + ".out"));

            verifier.verify();

            System.out.println(" Done.");
        }
        catch (TranscriptVerificationException e)
        {
            throw e;
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
            catch (TranscriptVerificationException e)
            {
                throw e;
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
            catch (TranscriptVerificationException e)
            {
                throw e;
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
            catch (TranscriptVerificationException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new TranscriptVerificationException("Signature check failed on  " + file.getPath() + ": " + e.getMessage(), e);
            }
        }

        return transcripts;
    }

    private static class CSVVerifier
    {
        private final File mapProperties;
        private final File pointFile;

        public CSVVerifier(File mapProperties, File pointFile)
        {
            this.mapProperties = mapProperties;
            this.pointFile = pointFile;
        }

        public void verify()
            throws JSONException, JSONIOException, IOException, TranscriptVerificationException
        {
            BallotUnpacker unpacker = new BallotUnpacker(mapProperties);

            ASN1InputStream aIn = new ASN1InputStream(new FileInputStream(pointFile));

            String baseName = pointFile.getName().substring(0, pointFile.getName().lastIndexOf('.'));
            String[] details = baseName.split("_"); // The second part of the name tells us which type the race is

            BufferedReader bfIn = new BufferedReader(new FileReader(new File(pointFile.getParentFile(), baseName + "." + unpacker.getSuffix(details[0], details[1], details[2]) + ".csv")));
            int ballotLength = unpacker.getBallotLength(details[0], details[1], details[2]);

            int lineNumber = 1;
            Object o;
            while ((o = aIn.readObject()) != null)
            {
                PointSequence seq = PointSequence.getInstance(CustomNamedCurves.getByName("secp256r1").getCurve(), o);
                ECPoint[]     points = seq.getECPoints();

                List<Integer> candidates = new ArrayList<>();
                int maxCandidateID = 0;

                for (int i = 0; i != points.length; i++)
                {
                    int[] votes = unpacker.lookup(details[0], details[1], details[2], points[i]);
                    for  (int j = 0; j != votes.length; j++)
                    {
                        candidates.add(votes[j]);
                        if (votes[j] > maxCandidateID)
                        {
                            maxCandidateID = votes[j];
                        }
                    }
                }

                int[] preferences = new int[ballotLength];
                int   preference = 1;
                for (int i = 0; i != candidates.size(); i++)
                {
                    preferences[candidates.get(i) - 1] = preference++;
                }

                StringBuilder sBuild = new StringBuilder();
                for (int i = 0; i != preferences.length; i++)
                {
                    if (i != 0)
                    {
                        sBuild.append(",");
                    }
                    if (preferences[i] != 0)
                    {
                        sBuild.append(Integer.toString(preferences[i]));
                    }
                }

                String recorded = bfIn.readLine();
                if (!sBuild.toString().equals(recorded))
                {
                    throw new TranscriptVerificationException("Recorded CSV ballot (" + lineNumber + ") \"" + recorded + "\" does not match EC output \"" + sBuild.toString() +"\"");
                }

                lineNumber++;
            }

            aIn.close();
            bfIn.close();

        }
    }
}
