package org.cryptoworkshop.ximix.mixnet.service;

import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.MoveMessage;
import org.cryptoworkshop.ximix.common.service.Service;
import org.cryptoworkshop.ximix.common.service.ServiceContext;
import org.cryptoworkshop.ximix.mixnet.board.BulletinBoardRegistry;
import org.cryptoworkshop.ximix.mixnet.task.TransformShuffleAndMoveTask;

public class NodeCommandService
    implements Service
{
    private final ServiceContext serviceContext;
    private final BulletinBoardRegistry boardRegistry;

    public NodeCommandService(ServiceContext context)
    {
        this.serviceContext = context;
        this.boardRegistry = (BulletinBoardRegistry)context.getParameter(ServiceContext.BULLETIN_BOARD_REGISTRY);
    }

    public MessageReply handle(Message message)
    {
        switch (((CommandMessage)message).getType())
        {
        case SHUFFLE_AND_MOVE_BOARD_TO_NODE:
            MoveMessage moveMessage = MoveMessage.getInstance(message.getPayload());
            serviceContext.scheduleTask(new TransformShuffleAndMoveTask(serviceContext, boardRegistry, moveMessage));
            break;
        default:
            System.err.println("unknown command");
        }
        return new MessageReply(MessageReply.Type.OKAY);
    }

    public boolean isAbleToHandle(Enum type)
    {
        return false; // type == Message.Type.UPLOAD_TO_BOARD;
    }
}
