package org.cryptoworkshop.ximix.console.util.vote;

import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Strings;
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
    private final Map<String, CandidateIndex> candidateTable = new HashMap<>();
    private final ECPoint             paddingPoint;
    private final Set<String>         useCandidateList = new HashSet<>();

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
            if (name.startsWith("use.direct"))
            {
                useCandidateList.add(Strings.toLowerCase(mapProperties.getProperty(name)));
            }
        }

        File candidateDir = new File(unpackerConfig.getParent(), mapProperties.getProperty("candidate.tables"));

        File[] tables = candidateDir.listFiles(new FilenameFilter()
        {
            @Override
            public boolean accept(File dir, String name)
            {
                return name.endsWith(".json") || name.endsWith(".cid");
            }
        });

        // nothing is done with these just yet. They may be required if there are late changes
        // to the ballot draw.
        for (File table : tables)
        {
            JSONObject candidateData = IOUtils.readJSONObjectFromFile(table.getPath());

            JSONArray candidates = candidateData.getJSONArray("CandidateIds");
            List<ECPoint> candidateList = new ArrayList<>();

            for (int i = 0; i != candidates.length(); i++)
            {
                JSONObject candidateID = candidates.getJSONObject(i);

                candidateList.add(curve.createPoint(new BigInteger(candidateID.getString("x"), 16), new BigInteger(candidateID.getString("y"), 16)));
            }

            candidateTable.put(table.getName().substring(0, table.getName().indexOf('.')), new CandidateIndex(candidateData.getString("RaceName"), candidateData.getString("DistrictName"), candidateList));
        }
    }

    public String getSuffix(String gid, String type, String meta)
    {
         return candidateTable.get(gid + "_" + type + "_" + meta).getSuffix();
    }

    /**
     * Return an array of votes, can be empty if none were made. The list will be
     * candidate numbers in ballot order as preferences.
     *
     * @param type  indicator for the packing table to use.
     * @param point a possibly packed set of indexes.
     * @return an array of votes based on ballot order
     */
    public int[] lookup(String gid, String type, String meta, ECPoint point)
    {
        Lookup lookUp = lookupMap.get(type.toLowerCase());

        if (useCandidateList.contains(Strings.toLowerCase(type)))
        {
            List<ECPoint> candidateList = candidateTable.get(gid + "_" + type + "_" + meta).getCandidateList();

            for (int i = 0; i != candidateList.size(); i++)
            {
                if (candidateList.get(i).equals(point))
                {
                    return new int[]{i + 1};
                }
            }
        }

        if (point.equals(paddingPoint))
        {
            return new int[0];
        }

        byte[] indexes = lookUp.find(point);

        //
        // truncate zeroes
        int end = indexes.length - 1;
        while (end >= 0 && indexes[end] == 0)
        {
            end--;
        }

        // this list is candidate numbers in ballot order as preferences.
        int[] values = new int[end + 1];

        for (int i = 0; i != values.length; i++)
        {
            values[i] = indexes[i];
        }

        return values;
    }

    public int getBallotLength(String gid, String type, String meta)
    {
        return candidateTable.get(gid + "_" + type + "_" + meta).getCandidateList().size();
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
            byte[] encoding = bsf.binarySearch(point.getEncoded(true));
            if (encoding == null)
            {
                // TODO: logging
                System.err.println(point.getXCoord().toBigInteger().toString(16) + " " + point.getYCoord().toBigInteger().toString(16));
                return null;
            }
            return BinarySearchFile.convertToPlain(encoding, packingSize);
        }
    }

    private class CandidateIndex
    {
        private final String raceName;
        private final String districtName;
        private final List<ECPoint> candidateList;

        CandidateIndex(String raceName, String districtName, List<ECPoint> candidateList)
        {
            this.raceName = raceName;
            if (raceName.equals(districtName))
            {
                this.districtName = null;
            }
            else
            {
                this.districtName = districtName;
            }
            this.candidateList = candidateList;
        }

        public String getSuffix()
        {
            return (districtName != null) ? raceName + "_" + districtName : raceName;
        }

        public List<ECPoint> getCandidateList()
        {
            return candidateList;
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

            System.err.println(unpacker.lookup(details[0], details[1], details[2], seq.getECPoints()[0]));
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
