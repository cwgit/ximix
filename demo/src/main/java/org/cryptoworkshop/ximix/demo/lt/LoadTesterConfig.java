package org.cryptoworkshop.ximix.demo.lt;

import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.List;

/**
 *
 */
public class LoadTesterConfig
{
    private final List<RaceConfig> races = new ArrayList<>();


    public List<RaceConfig> getRaces()
    {
        return races;
    }

    public LoadTesterConfig(Node parent)
    {
        NodeList nl = parent.getChildNodes();

        for (int t = 0; t < nl.getLength(); t++)
        {
            Node node = nl.item(t);
            String n = node.getNodeName();
            if ("races".equals(n))
            {
                races.add(new RaceConfig(node));
            }
        }



    }


    public static class RaceConfig
    {
        private int numBallots;
        private int candidates;

        public RaceConfig(Node parent)
        {
            NodeList nl = parent.getChildNodes();
            for (int t = 0; t < nl.getLength(); t++)
            {
                Node node = nl.item(t);
                if ("number".equals(node.getNodeName()))
                {
                    numBallots = Integer.valueOf(node.getTextContent());
                }
                else if ("candidates".equals(node.getNodeName()))
                {
                    candidates = Integer.valueOf(node.getTextContent());
                }
            }
        }

        public int getNumBallots()
        {
            return numBallots;
        }

        public int getCandidates()
        {
            return candidates;
        }
    }

}
