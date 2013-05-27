package org.cryptoworkshop.ximix.mixnet.service;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.UploadMessage;
import org.cryptoworkshop.ximix.common.service.Service;
import org.cryptoworkshop.ximix.common.service.ServiceContext;
import org.cryptoworkshop.ximix.mixnet.board.BulletinBoard;
import org.cryptoworkshop.ximix.mixnet.task.UploadTask;

public class NodeUploadService
    implements Service
{
    private final ServiceContext serviceContext;
    private Executor boardUpdateExecutor = Executors.newSingleThreadExecutor();

    private Map<String, BulletinBoard> boards = new HashMap<String, BulletinBoard>();

    public NodeUploadService(ServiceContext context)
    {
         this.serviceContext = context;
    }

    public BulletinBoard getBoard(final String boardName)
    {
        synchronized (boards)
        {
            BulletinBoard board = boards.get(boardName);

            // TODO: probably don't want to allow add on demand, should have config up front or special command.
            if (board == null)
            {
                board = new BulletinBoard(boardName, boardUpdateExecutor);

                boards.put(boardName, board);
            }

            return board;
        }
    }

    public MessageReply handle(Message message)
    {
        switch (message.getType())
        {
        case UPLOAD_TO_BOARD:
            UploadMessage uploadMessage = UploadMessage.getInstance(message.getPayload());
            serviceContext.scheduleTask(new UploadTask(serviceContext, getBoard(uploadMessage.getBoardName()), uploadMessage));
            break;
        default:
            System.err.println("unknown command");
        }
        return new MessageReply(MessageReply.Type.OKAY);
    }

    public boolean isAbleToHandle(Message.Type type)
    {
        return type == Message.Type.UPLOAD_TO_BOARD;
    }
}
