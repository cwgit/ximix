package org.cryptoworkshop.ximix.installer;

import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;


/**
 *
 */
public class Util {


    /**
     * Traverse children.
     *
     * @param parent    The parent.
     * @param traversal The traversal callback.
     */
    public static void traverseChildren(Node parent, NodeTraversal traversal) {
        NodeList nl = parent.getChildNodes();
        for (int t = 0; t < nl.getLength(); t++) {
            traversal.node(nl.item(t));
        }
    }

    /**
     * Traverse the attributes of a node.
     *
     * @param parent    The parent.
     * @param traversal The traversal callback.
     */
    public static void traverseAttributes(Node parent, NodeTraversal traversal) {
        NamedNodeMap nnM = parent.getAttributes();
        for (int t = 0; t < nnM.getLength(); t++) {
            traversal.node(nnM.item(t));
        }
    }

    /**
     * NodeTraversal callback.
     */
    public static interface NodeTraversal {
        void node(Node n);
    }
}
