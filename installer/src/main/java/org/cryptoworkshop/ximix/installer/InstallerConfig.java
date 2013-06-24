package org.cryptoworkshop.ximix.installer;

import org.w3c.dom.Node;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Installer config.
 */
public class InstallerConfig {

    /**
     * The install location on the file system.
     */
    private File installLocation = null;

    /**
     * The in archive source location.
     */
    private String inArchiveLocation = null;


    public InstallerConfig() {

    }


    /**
     * An installation is a collection of operations in the order they will be executed.
     */
    public static class Installation {

        private String id = null;
        private String name = null;
        private String description = null;


        private List<Object> operations = new ArrayList<>();

        public Installation(Node n) {
            Util.traverseChildren(n, new Util.NodeTraversal() {
                @Override
                public void node(Node n) {
                    if ("movements".equals(n.getNodeName())) {
                        operations.add(new MovementCollection(n));
                    } else if ("movement".equals(n.getNodeName())) {
                        operations.add(new Movement(n));
                    } else if ("id".equals(n.getNodeName())) {
                        id = n.getTextContent();
                    } else if ("name".equals(n.getNodeName())) {
                        name = n.getTextContent();
                    } else if ("description".equals(n.getNodeName())) {
                        description = n.getTextContent();
                    }
                }
            });
        }

    }

    /**
     * A collection of movements.
     */
    public static class MovementCollection {
        private Integer id = null;
        private List<Movement> movements = new ArrayList<>();


        public MovementCollection(Node n) {
            Util.traverseChildren(n, new Util.NodeTraversal() {
                @Override
                public void node(Node n) {
                    if ("id".equals(n.getNodeName())) {
                        id = Integer.valueOf(n.getTextContent());
                    } else if ("movement".equals(n.getNodeName())) {
                        movements.add(new Movement(n));
                    }
                }
            });
        }

        public Integer getId() {
            return id;
        }

        public void setId(Integer id) {
            this.id = id;
        }

        public List<Movement> getMovements() {
            return movements;
        }

        public void setMovements(List<Movement> movements) {
            this.movements = movements;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            MovementCollection that = (MovementCollection) o;

            if (id != null ? !id.equals(that.id) : that.id != null) return false;

            return true;
        }

        @Override
        public int hashCode() {
            return id != null ? id.hashCode() : 0;
        }
    }


    /**
     * Defines a specific movement from the Archive to the target file system.
     */
    public static class Movement {
        private boolean recursive = false;
        private String src = null;
        private String dest = null;
        private String destName = null;

        public Movement() {

        }

        public Movement(Node node) {
            Util.traverseAttributes(node, new Util.NodeTraversal() {
                @Override
                public void node(Node n) {
                    if ("src".equals(n.getNodeName())) {
                        src = n.getTextContent();
                    } else if ("dest".equals(n.getNodeName())) {
                        dest = n.getTextContent().trim();
                    } else if ("destName".equals(n.getNodeName())) {
                        destName = n.getTextContent().trim();
                    }
                }
            });
        }
    }

}
