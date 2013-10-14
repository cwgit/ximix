package org.cryptoworkshop.ximix.node.mixnet.board;

/**
 * Listener for objects that monitor board changes,
 */
public interface BulletinBoardChangeListener
{
    /**
     * Signal the addition of messages.
     *
     * @param bulletinBoard the board that had the messages added.
     * @param count the number of messages added.
     */
    void messagesAdded(BulletinBoard bulletinBoard, int count);

    /**
     * Signal the removal of messages.
     *
     * @param bulletinBoard the board that had the messages removed.
     * @param count the number of messages removed.
     */
    void messagesRemoved(BulletinBoardImpl bulletinBoard, int count);
}
