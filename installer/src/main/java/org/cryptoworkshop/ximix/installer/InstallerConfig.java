package org.cryptoworkshop.ximix.installer;

import org.cryptoworkshop.ximix.installer.ui.steps.AbstractInstallerStep;
import org.cryptoworkshop.ximix.installer.ui.steps.ConfirmStep;
import org.cryptoworkshop.ximix.installer.ui.steps.SelectInstallLocation;
import org.cryptoworkshop.ximix.installer.ui.steps.SelectNumberOfNodes;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Installer config.
 */
public class InstallerConfig
{

    private static HashMap<String, Class> idToStepClass = new HashMap<>();

    static
    {
        idToStepClass.put(SelectInstallLocation.ID, SelectInstallLocation.class);
        idToStepClass.put(SelectNumberOfNodes.ID, SelectNumberOfNodes.class);
        idToStepClass.put(ConfirmStep.ID, ConfirmStep.class);
    }

    private Installation installation = null;

    public InstallerConfig(Node n)
    {
        installation = new Installation(n);
        Util.traverseChildren(n, new Util.NodeTraversal()
        {
            @Override
            public void node(Node n)
            {
                if ("installation".equals(n.getNodeName()))
                {
                    installation = new Installation(n);
                }
            }
        });


    }

    public Installation getInstallation()
    {
        return installation;
    }

    public void setInstallation(Installation installation)
    {
        this.installation = installation;
    }

    /**
     * An installation is a collection of operations in the order they will be executed.
     */
    public static class Installation
    {

        private String id = null;
        private String name = null;
        private String description = null;
        private List<Object> operations = new ArrayList<>();
        private HashMap<String, Object> props = new HashMap<>();

        public Installation(Node n)
        {
            Util.traverseChildren(n, new Util.NodeTraversal()
            {
                @Override
                public void node(Node n)
                {
                    if ("movements".equals(n.getNodeName()))
                    {
                        operations.add(new MovementCollection(n));
                    } else if ("movement".equals(n.getNodeName()))
                    {
                        operations.add(new Movement(n));
                    } else if ("id".equals(n.getNodeName()))
                    {
                        id = n.getTextContent();
                    } else if ("name".equals(n.getNodeName()))
                    {
                        name = n.getTextContent();
                    } else if ("description".equals(n.getNodeName()))
                    {
                        description = n.getTextContent();
                    } else if ("step".equals(n.getNodeName()))
                    {
                        operations.add(new Step(n));
                    } else if ("property".equals(n.getNodeName()))
                    {
                        NamedNodeMap attr = n.getAttributes();

                        String name = attr.getNamedItem("name").getTextContent();


                        //
                        // Properties can be overridden from command line using -D<name>=<value
                        //

                        String value = System.getProperty(name,null);

                        if (attr.getNamedItem("value") != null)
                        {
                            value = attr.getNamedItem("value").getTextContent();
                        }

                        String type = attr.getNamedItem("type").getTextContent();
                        switch (type)
                        {
                            case "int":
                                props.put(
                                        attr.getNamedItem("name").getTextContent(),
                                        Integer.valueOf(attr.getNamedItem("value").getTextContent())
                                );
                                break;

                            case "string":
                                props.put(
                                        attr.getNamedItem("name").getTextContent(),
                                        attr.getNamedItem("value").getTextContent()
                                );
                                break;

                            case "file":
                                props.put(
                                        attr.getNamedItem("name").getTextContent(),
                                        new File(attr.getNamedItem("value").getTextContent())
                                );
                                break;
                        }

                    }
                }
            });
        }

        public String getId()
        {
            return id;
        }

        public void setId(String id)
        {
            this.id = id;
        }

        public String getName()
        {
            return name;
        }

        public void setName(String name)
        {
            this.name = name;
        }

        public String getDescription()
        {
            return description;
        }

        public void setDescription(String description)
        {
            this.description = description;
        }

        public List<Object> getOperations()
        {
            return operations;
        }

        public void setOperations(List<Object> operations)
        {
            this.operations = operations;
        }
    }

    public static class Step
    {
        private AbstractInstallerStep stepInstance = null;

        public Step()
        {

        }

        public Step(Node n)
        {
            Util.traverseAttributes(n, new Util.NodeTraversal()
            {
                @Override
                public void node(Node n)
                {
                    if ("name".equals(n.getNodeName()))
                    {
                        String id = n.getTextContent();
                        if (!idToStepClass.containsKey(id))
                        {
                            throw new RuntimeException("Step id " + id + " was not found.");
                        }
                        try
                        {
                            stepInstance = (AbstractInstallerStep) idToStepClass.get(id).newInstance();
                        } catch (Exception e)
                        {

                            new RuntimeException(e);

                        }

                    }
                }
            });
        }

        public AbstractInstallerStep getStepInstance()
        {
            return stepInstance;
        }

        public void setStepInstance(AbstractInstallerStep stepInstance)
        {
            this.stepInstance = stepInstance;
        }
    }

    /**
     * A collection of movements.
     */
    public static class MovementCollection
    {
        private Integer id = null;
        private List<Movement> movements = new ArrayList<>();


        public MovementCollection(Node n)
        {
            Util.traverseChildren(n, new Util.NodeTraversal()
            {
                @Override
                public void node(Node n)
                {
                    if ("id".equals(n.getNodeName()))
                    {
                        id = Integer.valueOf(n.getTextContent());
                    } else if ("movement".equals(n.getNodeName()))
                    {
                        movements.add(new Movement(n));
                    }
                }
            });
        }

        public Integer getId()
        {
            return id;
        }

        public void setId(Integer id)
        {
            this.id = id;
        }

        public List<Movement> getMovements()
        {
            return movements;
        }

        public void setMovements(List<Movement> movements)
        {
            this.movements = movements;
        }

        @Override
        public boolean equals(Object o)
        {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            MovementCollection that = (MovementCollection) o;

            if (id != null ? !id.equals(that.id) : that.id != null) return false;

            return true;
        }

        @Override
        public int hashCode()
        {
            return id != null ? id.hashCode() : 0;
        }
    }

    /**
     * Defines a specific movement from the Archive to the target file system.
     */
    public static class Movement
    {
        private boolean recursive = false;
        private String src = null;
        private String dest = null;
        private String destName = null;

        public Movement()
        {

        }

        public Movement(Node node)
        {
            Util.traverseAttributes(node, new Util.NodeTraversal()
            {
                @Override
                public void node(Node n)
                {
                    if ("src".equals(n.getNodeName()))
                    {
                        src = n.getTextContent();
                    } else if ("dest".equals(n.getNodeName()))
                    {
                        dest = n.getTextContent().trim();
                    } else if ("destName".equals(n.getNodeName()))
                    {
                        destName = n.getTextContent().trim();
                    }   else if ("recursive".equals(n.getNodeName()))
                    {
                        recursive = Boolean.valueOf(n.getTextContent().trim());
                    }
                }
            });
        }
    }

}
