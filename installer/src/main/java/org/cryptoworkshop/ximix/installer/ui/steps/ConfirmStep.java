package org.cryptoworkshop.ximix.installer.ui.steps;

/**
 *  Confirm before install.
 */
public class ConfirmStep extends AbstractInstallerStep
{

    public static final String ID = "confirm_step";

    public ConfirmStep()
    {
        super();
        this.title = "Confirm installation.";
        this.content = "";
        this.inputType = InputType.STEP_THROUGH;
    }

    @Override
    public String acceptValue(Object value)
    {
        return null;
    }

    @Override
    public Object getDefault()
    {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }
}
