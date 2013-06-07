package org.cryptoworkshop.ximix.mixnet.service;

import org.cryptoworkshop.ximix.common.message.ClientMessage;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.UploadMessage;
import org.cryptoworkshop.ximix.common.service.Service;
import org.cryptoworkshop.ximix.common.service.ServiceContext;
import org.cryptoworkshop.ximix.mixnet.board.BulletinBoardRegistry;
import org.cryptoworkshop.ximix.mixnet.task.UploadTask;

public class NodeUploadService
    implements Service
{
    private final ServiceContext serviceContext;
    private final BulletinBoardRegistry boardRegistry;

    public NodeUploadService(ServiceContext context)
    {
        this.serviceContext = context;
        this.boardRegistry = (BulletinBoardRegistry)context.getParameter(ServiceContext.BULLETIN_BOARD_REGISTRY);
    }

    public MessageReply handle(Message message)
    {
        switch (((ClientMessage)message).getType())
        {
        case UPLOAD_TO_BOARD:
            UploadMessage uploadMessage = UploadMessage.getInstance(message.getPayload());
            serviceContext.scheduleTask(new UploadTask(serviceContext, boardRegistry, uploadMessage));
            break;
        default:
            System.err.println("unknown command");
        }
        return new MessageReply(MessageReply.Type.OKAY);
    }

    public boolean isAbleToHandle(Enum type)
    {
        return type == ClientMessage.Type.UPLOAD_TO_BOARD;
    }
}
