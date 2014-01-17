package org.cryptoworkshop.ximix.console.util.vote;

import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.common.asn1.board.PointSequence;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import uk.ac.surrey.cs.tvs.utils.io.IOUtils;
import uk.ac.surrey.cs.tvs.utils.io.exceptions.JSONIOException;
import uk.ac.surrey.cs.tvs.votepacking.search.BinarySearchFile;

/**
 * This class is still very much under development!!!
 */
public class VoteUnpacker
{
    private final ECCurve             curve;
    private final Map<String, Lookup> lookupMap = new HashMap<>();
    private final ECPoint             paddingPoint;

    public VoteUnpacker(File unpackerConfig)
        throws IOException, JSONException, JSONIOException
    {
        Properties mapProperties = new Properties();

        mapProperties.load(new FileInputStream(unpackerConfig));

        curve = CustomNamedCurves.getByName(mapProperties.getProperty("curve")).getCurve();

        JSONObject pad = IOUtils.readJSONObjectFromFile(new File(unpackerConfig.getParent(), mapProperties.getProperty("padding.file")).getPath());

        paddingPoint = curve.createPoint(new BigInteger(pad.getString("x"), 16), new BigInteger(pad.getString("y"), 16));

        for (Enumeration en = mapProperties.propertyNames(); en.hasMoreElements();)
        {
            String name = (String)en.nextElement();
            if (name.startsWith("table.") && name.endsWith(".file"))
            {
                String base = name.substring(0, name.indexOf('.', "table.".length() + 1));

                lookupMap.put(base.substring("table.".length()).toLowerCase(), new Lookup(unpackerConfig.getParentFile(), mapProperties, base));
            }
        }

        File candidateDir = new File(unpackerConfig.getParent(), mapProperties.getProperty("candidate.tables"));

        File[] tables = candidateDir.listFiles(new FilenameFilter()
        {
            @Override
            public boolean accept(File dir, String name)
            {
                return name.endsWith(".json");
            }
        });

        // nothing is done with these just yet. They may be required if there are late changes
        // to the ballot draw.
        for (File table : tables)
        {
            JSONObject candidateData = IOUtils.readJSONObjectFromFile(table.getPath());

            JSONArray candidates = candidateData.getJSONArray("CandidateIds");
//            for (int i = 0; i != candidates.length(); i++)
//            {
//                System.err.println(candidates.get(i));
//            }
        }
    }

    /**
     * Return an array of votes, with 0 indicating no vote was given.
     *
     * @param type indicator for the packing table to use.
     * @param point a possibly packed set of indexes.
     * @return an array of votes based on ballot order
     */
    public int[] lookup(String type, ECPoint point)
    {
        Lookup lookUp = lookupMap.get(type.toLowerCase());

        if (point.equals(paddingPoint))
        {
            return new int[lookUp.packingSize];
        }

        byte[] indexes = lookUp.find(point);

        // TODO: at the moment the candidate files are not needed, they're in the config in
        // case the ballot position needs to be added. At the moment we take the ballot position
        // as the index + 1.
        int[] values = new int[lookUp.packingSize];

        for (int i = 0; i != indexes.length; i++)
        {
            values[i] = indexes[i] + 1;
        }

        return values;
    }

    private class Lookup
    {
        private final BinarySearchFile bsf;
        private final int packingSize;

        Lookup(File baseDir, Properties config, String mapType)
            throws IOException, JSONException, JSONIOException
        {
            this.bsf = new BinarySearchFile(new File(baseDir, config.getProperty(mapType + ".file")), Integer.parseInt(config.getProperty(mapType + ".linelength")));

            this.packingSize = Integer.parseInt(config.getProperty(mapType + ".packing"));
        }

        byte[] find(ECPoint point)
        {
            return BinarySearchFile.convertToPlain(bsf.binarySearch(point.getEncoded(true)), packingSize);
        }
    }

    public static void main(String[] args)
        throws Exception
    {
        VoteUnpacker unpacker = new VoteUnpacker(new File(args[0]));

        File inputVotes = new File(args[1]);

        ASN1InputStream aIn = new ASN1InputStream(new FileInputStream(inputVotes));

        String[] details = args[1].split("_");

        Object o;
        while ((o = aIn.readObject()) != null)
        {
            PointSequence seq = PointSequence.getInstance(CustomNamedCurves.getByName("secp256r1").getCurve(), o);

            System.err.println(unpacker.lookup(details[1], seq.getECPoints()[0]));
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
