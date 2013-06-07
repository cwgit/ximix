package org.cryptoworkshop.ximix.mixnet.service;

public interface TransferBoardService
{
    void signalStart(String boardName);

    void uploadMessage(byte[] message);

    void signalEnd(String boardName);
}
