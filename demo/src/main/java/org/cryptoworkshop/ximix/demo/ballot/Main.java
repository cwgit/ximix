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
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
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

    private static void generateBallots(String baseName, Random rand, int ballotSize, ECElGamalEncryptor encryptor, ECDomainParameters ecParams, SecureRandom pointRandom)
        throws IOException
    {
        File ballotFile = new File(baseName + ".blt");
        File candidateFile = new File(baseName + "." + "candidates.json");

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

        BufferedWriter cWrt = new BufferedWriter(new FileWriter(candidateFile));

        cWrt.write("{");
        cWrt.newLine();

        cWrt.write("    \"RaceId\": \"" + baseName + "\",");
        cWrt.newLine();

        cWrt.write("    \"RaceName\": \"Bass\",");
        cWrt.newLine();

        cWrt.write("    \"RaceType\": \"LA\",");
        cWrt.newLine();

        cWrt.write("    \"CandidateIds\": [");
        cWrt.newLine();

        for (int j = 0; j != candidateNumbers.size(); j++)
        {
            ECPoint candidate = candidateNumbers.get(j);

            cWrt.write("        {");
            cWrt.newLine();
            cWrt.write("            \"x\" : \"" + candidate.getAffineXCoord().toBigInteger().toString(16) + "\",");
            cWrt.newLine();
            cWrt.write("            \"y\" : \"" + candidate.getAffineYCoord().toBigInteger().toString(16) + "\"");
            cWrt.newLine();
            if (j < candidateNumbers.size() - 1)
            {
                cWrt.write("        },");
            }
            else
            {
                cWrt.write("        }");
            }
            cWrt.newLine();
        }

        cWrt.write("    ]");
        cWrt.newLine();

        cWrt.write("}");
        cWrt.newLine();
        cWrt.close();
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
            String baseName = "REGION-" + fmt.format(i) + "_LA";

            generateBallots(baseName, new Random(i), ballotSize, encryptor, pubKey.getParameters(), new SecureRandom());
        }
    }
}
