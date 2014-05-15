package org.cryptoworkshop.ximix.client;

/**
 * A general status object for providing shuffle details.
 */
public class ShuffleStatus
{
    private final boolean errorStatus;
    private final String message;
    private final String nodeName;
    private final int stepNo;
    private final Throwable cause;

    public ShuffleStatus(String message, String nodeName, int stepNo)
    {
        this.errorStatus = false;
        this.message = message;
        this.nodeName = nodeName;
        this.stepNo = stepNo;
        this.cause = null;
    }

    public ShuffleStatus(String message, String nodeName, Throwable cause)
    {
        this.errorStatus = true;
        this.message = message;
        this.nodeName = nodeName;
        this.stepNo = -1;
        this.cause = cause;
    }

    public boolean isErrorStatus()
    {
        return errorStatus;
    }

    public String getMessage()
    {
        return message;
    }

    public String getNodeName()
    {
        return nodeName;
    }

    public int getStepNo()
    {
        return stepNo;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
