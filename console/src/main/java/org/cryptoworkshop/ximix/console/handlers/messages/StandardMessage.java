package org.cryptoworkshop.ximix.console.handlers.messages;

/**
 * Base of all message objects.
 */
public class StandardMessage
{

    private boolean successful = false;
    private int errorCode = 0;
    private String message = null;

    public StandardMessage()
    {

    }

    public StandardMessage(boolean successful, String message)
    {
        this.errorCode = 0;
        this.successful = successful;
        this.message = message;
    }

    public boolean isSuccessful()
    {
        return successful;
    }

    public void setSuccessful(boolean successful)
    {
        this.successful = successful;
    }

    public int getErrorCode()
    {
        return errorCode;
    }

    public void setErrorCode(int errorCode)
    {
        this.errorCode = errorCode;
    }

    public String getMessage()
    {
        return message;
    }

    public void setMessage(String message)
    {
        this.message = message;
    }
}
