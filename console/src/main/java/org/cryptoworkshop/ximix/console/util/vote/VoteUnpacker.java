package org.cryptoworkshop.ximix.console.util.vote;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.common.asn1.board.PointSequence;
import org.json.JSONArray;
import org.json.JSONException;
import uk.ac.surrey.cs.tvs.utils.io.IOUtils;
import uk.ac.surrey.cs.tvs.utils.io.exceptions.JSONIOException;
import uk.ac.surrey.cs.tvs.votepacking.search.BinarySearchFile;

/**
 * This class is still very much under development!!!
 */
public class VoteUnpacker
{
    private final BinarySearchFile bsf;
    private final int              packingSize;
    private final ECCurve          curve;

    public VoteUnpacker(File unpackerConfig)
        throws IOException, JSONException, JSONIOException
    {
        Properties mapProperties = new Properties();

        mapProperties.load(new FileInputStream(unpackerConfig));

        bsf = new BinarySearchFile(new File(unpackerConfig.getParentFile(), mapProperties.getProperty("table.file")), Integer.parseInt(mapProperties.getProperty("table.linelength")));
        packingSize = Integer.parseInt(mapProperties.getProperty("table.packing"));

        JSONArray candidates = IOUtils.readJSONArrayFromFile(new File(unpackerConfig.getParentFile(), mapProperties.getProperty("candidate.identifiers")).getPath());

        for (int i = 0; i != candidates.length(); i++)
        {
            System.err.println(candidates.get(i));
        }

        curve = CustomNamedCurves.getByName(mapProperties.getProperty("curve")).getCurve();
    }

    public ECPoint[] lookup(ECPoint point)
    {
        byte[] indexes = BinarySearchFile.convertToPlain(bsf.binarySearch(point.getEncoded(true)), packingSize);

        for (int i = 0; i != indexes.length; i++)
        {
            System.err.println(indexes[i]);
        }
        return null;

    }

    public static void main(String[] args)
        throws Exception
    {
        VoteUnpacker unpacker = new VoteUnpacker(new File(args[0]));

        File inputVotes = new File(args[1]);

        ASN1InputStream aIn = new ASN1InputStream(new FileInputStream(inputVotes));

        Object o;
        while ((o = aIn.readObject()) != null)
        {
            PointSequence seq = PointSequence.getInstance(CustomNamedCurves.getByName("secp256r1").getCurve(), o);

            System.err.println(unpacker.lookup(seq.getECPoints()[0]));
        }


//        // Look up each sample packing and check it is found correctly
//        for (int i = 0; i < numberOfTests; i++) {
//          long innerStartTime = System.currentTimeMillis();
//          byte[] res = bsf.binarySearch(samplePacking.get(i).getEncoded(true));
//          if (res != null) {
//            String foundResult = Arrays.toString(BinarySearchFile.convertToPlain(res, blockSize));
//            String expected = Arrays.toString(expectedResult.get(i));
//
//            if (!foundResult.equals(expected)) {
//              logger.warn("Incorrect result); expected: {} found {}", expected, foundResult);
//              failure++;
//            }
//            else {
//              success++;
//            }
//          }
//          else {
//            failure++;
//            logger.warn("Result not found: expected: {} found null", Arrays.toString(expectedResult.get(i)));
//          }
//          long innerEndTime = System.currentTimeMillis();
//          long diff = innerEndTime - innerStartTime;
//
//          if (diff > maxSearchTime) {
//            maxSearchTime = diff;
//          }
//          if (diff < minSearchTime) {
//            minSearchTime = diff;
//          }
//        }
    }
}
