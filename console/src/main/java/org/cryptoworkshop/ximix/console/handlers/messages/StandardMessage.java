package org.cryptoworkshop.ximix.console.handlers.messages;

/**
 * Base of all message objects.
 */
public class StandardMessage {

    private boolean successful = false;
    private int errorCode = 0;
    private String errorMessage = null;

    public StandardMessage() {

    }

    public boolean isSuccessful() {
        return successful;
    }

    public void setSuccessful(boolean successful) {
        this.successful = successful;
    }

    public int getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(int errorCode) {
        this.errorCode = errorCode;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }
}
