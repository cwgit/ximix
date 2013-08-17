package org.cryptoworkshop.ximix.node.mixnet.board;

/**
 *
 */
public interface BulletinBoardChangeListener
{

    void messagesAdded(BulletinBoard bulletinBoard, int count);

    void messagesRemoved(BulletinBoardImpl bulletinBoard, int count);
}
