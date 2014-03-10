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
package org.cryptoworkshop.ximix.demo.ballot;

import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.bouncycastle.crypto.ec.ECElGamalEncryptor;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.client.KeyService;
import org.cryptoworkshop.ximix.client.connection.XimixRegistrar;
import org.cryptoworkshop.ximix.client.connection.XimixRegistrarFactory;
import org.cryptoworkshop.ximix.common.asn1.board.PairSequence;
import org.cryptoworkshop.ximix.common.util.EventNotifier;

/**
 * Generator for ballot files.
 */
public class Main
{
    private static ECPoint generatePoint(ECDomainParameters params, SecureRandom rand)
    {
        return params.getG().multiply(getRandomInteger(params.getN(), rand)).normalize();
    }

    private static BigInteger getRandomInteger(BigInteger n, SecureRandom rand)
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

    private static void generateBallots(File ballotDir, File candidateDir, String baseName, Random rand, int ballotSize, ECElGamalEncryptor encryptor, ECDomainParameters ecParams, SecureRandom pointRandom)
        throws IOException
    {
        File ballotFile = new File(ballotDir, baseName + ".blt");
        File candidateFile = new File(candidateDir, baseName + "." + "candidates.cid");

        int numberOfCandidates = 4 + rand.nextInt(10);

        List<ECPoint> candidateNumbers = new ArrayList<>(numberOfCandidates);

        for (int candidateNo = 0; candidateNo != numberOfCandidates; candidateNo++)
        {
            candidateNumbers.add(generatePoint(ecParams, pointRandom));
        }

        int numberOfBallots = ballotSize + rand.nextInt(ballotSize / 10);

        ECPair[][] ballots = new ECPair[numberOfBallots][];

        for (int ballotNo = 0; ballotNo != numberOfBallots; ballotNo++)
        {
            Collections.shuffle(candidateNumbers, rand);

            ECPair[] ballot = new ECPair[numberOfCandidates];

            for (int i = 0; i != ballot.length; i++)
            {
                ballot[i] = encryptor.encrypt(candidateNumbers.get(i));
            }

            ballots[ballotNo] = ballot;
        }

        OutputStream fOut = new BufferedOutputStream(new FileOutputStream(ballotFile));

        for (int j = 0; j != ballots.length; j++)
        {
            fOut.write(new PairSequence(ballots[j]).getEncoded());
        }

        fOut.close();

        createCandidateList(baseName, candidateFile, "ATL", candidateNumbers);
    }

    private static void generatePackedBallots(File ballotDir, File candidateDir, String baseName, Random rand, int ballotSize,
                                              ECElGamalEncryptor encryptor, ECDomainParameters ecParams, SecureRandom pointRandom, Map<Preferences, ECPoint> preferenceMap, ECPoint paddingPoint)
        throws IOException
    {
        File ballotFile = new File(ballotDir, baseName + ".blt");
        File candidateFile = new File(candidateDir, baseName + "." + "candidates.cid");

        int numberOfCandidates = 4 + rand.nextInt(10);

        List<ECPoint> candidateNumbers = new ArrayList<>(numberOfCandidates);

        for (int candidateNo = 0; candidateNo != numberOfCandidates; candidateNo++)
        {
            candidateNumbers.add(generatePoint(ecParams, pointRandom));
        }

        createCandidateList(baseName, candidateFile, "BTL", candidateNumbers);

        int numberOfBallots = ballotSize + rand.nextInt(ballotSize / 10);

        ECPair[][] ballots = new ECPair[numberOfBallots][];

        List<Byte>  preferences = new ArrayList<>();
        for (int i = 0; i != numberOfCandidates; i++)
        {
            preferences.add((byte)(i + 1));
        }

        for (int ballotNo = 0; ballotNo != numberOfBallots - 1; ballotNo++)
        {
            Collections.shuffle(preferences, rand);

            ECPair[] ballot = new ECPair[(preferences.size() + 2) / 3];

            int index = 0;
            for (int i = 0; i != ballot.length; i++)
            {
                if (preferences.size() - index >= 3)
                {
                    ballot[i] = encryptor.encrypt(preferenceMap.get(new Preferences(new byte[] { preferences.get(index++), preferences.get(index++), preferences.get(index++)})));
                }
                else if (preferences.size() - index == 2)
                {
                    ballot[i] = encryptor.encrypt(preferenceMap.get(new Preferences(new byte[] { preferences.get(index++), preferences.get(index++), 0 })));
                }
                else if (preferences.size() - index == 1)
                {
                    ballot[i] = encryptor.encrypt(preferenceMap.get(new Preferences(new byte[] { preferences.get(index++), 0, 0 })));
                }
            }

            ballots[ballotNo] = ballot;
        }

        // add a ballot of all zeroes at the end
        ECPair[] ballot = new ECPair[(preferences.size() + 2) / 3];

        for (int i = 0; i != ballot.length; i++)
        {
            ballot[i] = encryptor.encrypt(paddingPoint);
        }

        ballots[numberOfBallots - 1] = ballot;

        OutputStream fOut = new BufferedOutputStream(new FileOutputStream(ballotFile));

        for (int j = 0; j != ballots.length; j++)
        {
            fOut.write(new PairSequence(ballots[j]).getEncoded());
        }

        fOut.close();
    }

    private static void createCandidateList(String baseName, File candidateFile, String raceType, List<ECPoint> candidateNumbers)
        throws IOException
    {
        BufferedWriter cWrt = new BufferedWriter(new FileWriter(candidateFile));

        cWrt.write("{");
        cWrt.newLine();

        cWrt.write("    \"RaceId\": \"" + baseName + "\",");
        cWrt.newLine();

        cWrt.write("    \"RaceName\": \"" + baseName + "Race\",");
        cWrt.newLine();

        cWrt.write("    \"RaceType\": \"" + raceType + "\",");
        cWrt.newLine();

        cWrt.write("    \"DistrictName\": \"" + baseName.substring(0, baseName.indexOf('_')) + "\",");
        cWrt.newLine();

        cWrt.write("    \"CandidateIds\": [");
        cWrt.newLine();

        for (int j = 0; j != candidateNumbers.size(); j++)
        {
            outputPoint(cWrt, candidateNumbers.get(j), j == (candidateNumbers.size() - 1));
        }

        cWrt.write("    ]");
        cWrt.newLine();

        cWrt.write("}");
        cWrt.newLine();
        cWrt.close();
    }

    public static void outputPoint(BufferedWriter cWrt, ECPoint point, boolean isLast)
        throws IOException
    {
        cWrt.write("        {");
        cWrt.newLine();
        cWrt.write("            \"x\" : \"" + point.getAffineXCoord().toBigInteger().toString(16) + "\",");
        cWrt.newLine();
        cWrt.write("            \"y\" : \"" + point.getAffineYCoord().toBigInteger().toString(16) + "\"");
        cWrt.newLine();
        if (isLast)
        {
            cWrt.write("        }");
        }
        else
        {
            cWrt.write("        },");
        }
        cWrt.newLine();
    }

    public static void main(String[] args)
        throws Exception
    {
        if (args.length != 3)
        {
            System.err.println("Usage: Generate mixnet.xml number_of_regions avg_number_of_ballots");
            System.exit(1);
        }

        XimixRegistrar adminRegistrar = XimixRegistrarFactory.createAdminServiceRegistrar(new File(args[0]), new EventNotifier()
        {
            @Override
            public void notify(Level level, Throwable throwable)
            {
                System.err.print(level + " " + throwable.getMessage());
                throwable.printStackTrace(System.err);
            }

            @Override
            public void notify(Level level, Object detail)
            {
                System.err.println(level + " " + detail.toString());
            }

            @Override
            public void notify(Level level, Object detail, Throwable throwable)
            {
                System.err.println(level + " " + detail.toString());
                throwable.printStackTrace(System.err);
            }
        });

        File outDir = new File("electionData");

        if (!outDir.mkdir())
        {
            System.err.println("Unable to create directory \"electionData\"");
            System.exit(1);
        }

        File ballotDir = new File(outDir, "ballots");

        ballotDir.mkdir();

        File candidateDir = new File(outDir, "candidateTables");

        candidateDir.mkdir();

        KeyService keyGenerationService = adminRegistrar.connect(KeyService.class);

        byte[] encPubKey = keyGenerationService.fetchPublicKey("ECENCKEY");

        ECPublicKeyParameters pubKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(encPubKey);

        ECElGamalEncryptor encryptor = new ECElGamalEncryptor();

        encryptor.init(pubKey);

        DecimalFormat fmt = new DecimalFormat("000");

        int count = Integer.parseInt(args[1]);
        int ballotSize = Integer.parseInt(args[2]);

        for (int i = 0; i != count; i++)
        {
            String baseName = "REGION-" + fmt.format(i) + "_ATL_DEMO";

            generateBallots(ballotDir, candidateDir, baseName, new Random(i), ballotSize, encryptor, pubKey.getParameters(), new SecureRandom());
        }

        PackedBallotTableBuilder tableBuilder = new PackedBallotTableBuilder(new byte[20], pubKey.getParameters(), 20, 3);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        ECPoint paddingPoint = tableBuilder.build(bOut);

        Map<ECPoint, byte[]> packingMap = tableBuilder.getPackingMap();
        Map<Preferences, ECPoint> preferenceMap = new HashMap<>();

        for (ECPoint point : packingMap.keySet())
        {
            Preferences pref = new Preferences(packingMap.get(point));

            preferenceMap.put(pref, point);
        }

        FileOutputStream fOut = new FileOutputStream(new File(outDir, "BTL_Table"));

        fOut.write(bOut.toByteArray());

        fOut.close();

        BufferedWriter bWrt = new BufferedWriter(new FileWriter(new File(outDir, "paddingpoint.json")));

        outputPoint(bWrt, paddingPoint, true);

        bWrt.close();

        for (int i = 0; i != count; i++)
        {
            String baseName = "REGION-" + fmt.format(i) + "_BTL_DEMO";

            generatePackedBallots(ballotDir, candidateDir, baseName, new Random(i), ballotSize, encryptor, pubKey.getParameters(), new SecureRandom(), preferenceMap, paddingPoint);
        }

        keyGenerationService.shutdown();
        adminRegistrar.shutdown();

        bWrt = new BufferedWriter(new FileWriter(new File(outDir, "map.properties")));

        bWrt.write("curve: secp256r1"); bWrt.newLine();
        bWrt.write("use.direct: ATL"); bWrt.newLine();
        bWrt.write("padding.file: paddingpoint.json"); bWrt.newLine();
        bWrt.write("table.btl.file: BTL_Table"); bWrt.newLine();
        bWrt.write("table.btl.linelength: 36"); bWrt.newLine();
        bWrt.write("table.btl.packing: 3"); bWrt.newLine();
        bWrt.write("candidate.tables: candidateTables"); bWrt.newLine();

        bWrt.close();
    }

    private static class Preferences
    {
        private final byte[] prefs;

        Preferences(byte[] prefs)
        {
            this.prefs = prefs;
        }

        public boolean equals(Object o)
        {
            Preferences other = (Preferences)o;

            return Arrays.equals(prefs, other.prefs);
        }

        public int hashCode()
        {
            return 31 * (prefs[1] + 31 * prefs[0]) + prefs[2];
        }
    }
}
