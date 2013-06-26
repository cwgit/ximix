package org.cryptoworkshop.ximix.installer.ui.steps;

import java.util.HashMap;

/**
 * Confirm before install.
 */
public class ConfirmStep extends AbstractInstallerStep {

    public static final String ID = "confirm_step";

    public ConfirmStep() {
        super();
        this.title = "Confirm installation.";
        this.content = "";
        userInputs.add(new UserInput("Summary", InputType.SUMMARY,"summary"));
    }

    @Override
    public String acceptValue(HashMap<String, Object> value) {
        return null;
    }

    @Override
    public Object getDefault() {
        return null;
    }
}
