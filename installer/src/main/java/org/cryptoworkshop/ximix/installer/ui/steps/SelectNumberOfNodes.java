package org.cryptoworkshop.ximix.installer.ui.steps;

import java.util.HashMap;

/**
 *
 */
public class SelectNumberOfNodes extends AbstractInstallerStep {

    private int count = 1;

    public static final String ID = "number_of_nodes";

    public SelectNumberOfNodes() {
        super();
        this.title = "Please select the number of nodes";
        this.content = "This installer can install one of more nodes for testing, each node can be individually configured via its configuration file.";
        userInputs.add(new UserInput("Number of nodes", InputType.NUMBER, ID).setToolTip("Select the number of nodes to be installed.").setConstraints(new IntegerInputConstrains()));
    }

    @Override
    public Object getDefault() {
        return count;
    }

    @Override
    public String acceptValue(HashMap<String,Object> value) {
        try {
            int c = (Integer) value.get(ID);
            if (c < 1) {
                return "Value must be larger then 0";
            }

            count = c;

        } catch (Exception ex) {
            return "Invalid value";
        }

        return null;
    }


}
