package org.cryptoworkshop.ximix.mixnet.board;

/**
 *
 */
public interface BulletinBoardChangeListener
{

    void messagesAdded(BulletinBoard bulletinBoard, int count);

    void messagesRemoved(BulletinBoardImpl bulletinBoard, int count);
}
