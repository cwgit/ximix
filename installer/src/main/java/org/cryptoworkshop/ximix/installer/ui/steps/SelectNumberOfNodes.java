package org.cryptoworkshop.ximix.installer.ui.steps;

/**
 *
 */
public class SelectNumberOfNodes extends AbstractInstallerStep
{

    private int count = 1;

    public static final String ID = "number_of_nodes";

    public SelectNumberOfNodes()
    {
        super();
        this.title = "Please select the number of nodes";
        this.content = "This installer can install one of more nodes for testing, each node can be individually configured via its configuration file.";
        this.inputType = InputType.NUMBER;
    }

    @Override
    public Object getDefault()
    {
        return count;
    }

    @Override
    public String acceptValue(Object value)
    {
        try
        {
            int c = (Integer)value;
            if (c < 1)
            {
                return "Value must be larger then 0";
            }

            count = c;

        } catch (Exception ex)
        {
            return "Invalid value";
        }

        return null;
    }


}
