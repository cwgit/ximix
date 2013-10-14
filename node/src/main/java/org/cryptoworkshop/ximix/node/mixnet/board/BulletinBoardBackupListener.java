package org.cryptoworkshop.ximix.node.mixnet.board;

/**
 * Listener for objects that back up board data.
 */
public interface BulletinBoardBackupListener
{
    /**
     * Signal a board has been cleared.
     *
     * @param bulletinBoard the board that was cleared.
     */
     void cleared(BulletinBoard bulletinBoard);

    /**
     * Signal a board has had a message posted to it.
     *
     * @param bulletinBoard the board that was cleared.
     * @param index the index the message was posted at.
     * @param message the data representing the message posted.
     */
     void messagePosted(BulletinBoard bulletinBoard, int index, byte[] message);
}
