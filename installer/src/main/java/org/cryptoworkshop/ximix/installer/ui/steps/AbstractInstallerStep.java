package org.cryptoworkshop.ximix.installer.ui.steps;

import java.util.HashMap;

/**
 *
 */
public abstract class AbstractInstallerStep
{
    protected String title = null;
    protected String content = null;
    protected HashMap<String, String> toolTips = null;

    public abstract String acceptValue(Object value);

    public enum InputType {STRING, NUMBER, LIST_SINGLE, LIST_MULTI, STEP_THROUGH, FILE};

    protected InputType inputType = InputType.STRING;

    public AbstractInstallerStep() {

    }

    public abstract Object getDefault();


    public String getTitle()
    {
        return title;
    }

    public void setTitle(String title)
    {
        this.title = title;
    }

    public String getContent()
    {
        return content;
    }

    public void setContent(String content)
    {
        this.content = content;
    }

    public HashMap<String, String> getToolTips()
    {
        return toolTips;
    }

    public void setToolTips(HashMap<String, String> toolTips)
    {
        this.toolTips = toolTips;
    }
}
