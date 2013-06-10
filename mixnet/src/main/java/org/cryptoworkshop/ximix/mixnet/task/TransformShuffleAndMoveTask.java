/**
 * Copyright 2013 Crypto Workshop Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.cryptoworkshop.ximix.mixnet.task;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.MoveMessage;
import org.cryptoworkshop.ximix.common.message.UploadMessage;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.common.service.ServicesConnection;
import org.cryptoworkshop.ximix.mixnet.board.BulletinBoard;
import org.cryptoworkshop.ximix.mixnet.board.BulletinBoardRegistry;
import org.cryptoworkshop.ximix.mixnet.transform.MultiColumnRowTransform;
import org.cryptoworkshop.ximix.mixnet.transform.Transform;

public class TransformShuffleAndMoveTask
    implements Runnable
{
    private final NodeContext nodeContext;
    private final MoveMessage message;
    private final BulletinBoardRegistry boardRegistry;

    public TransformShuffleAndMoveTask(NodeContext nodeContext, BulletinBoardRegistry boardRegistry, MoveMessage message)
    {
        this.nodeContext = nodeContext;
        this.boardRegistry = boardRegistry;
        this.message = message;
    }

    public void run()
    {
        BulletinBoard board = boardRegistry.getBoard(message.getBoardName());
        Transform transform = new MultiColumnRowTransform();

        // TODO: need to fetch actual public key here.
        X9ECParameters params = SECNamedCurves.getByName("secp256r1");

        ECKeyPairGenerator kpGen = new ECKeyPairGenerator();

        kpGen.init(new ECKeyGenerationParameters(new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed()), new SecureRandom()));

        AsymmetricCipherKeyPair kp =  kpGen.generateKeyPair();
        transform.init(kp.getPublic());

        List<byte[]> transformedMessages = new ArrayList<byte[]>();

        for (byte[] message : board)
        {
            byte[] transformed = transform.transform(message);

            transformedMessages.add(transformed);
        }

        try
        {
            ServicesConnection peerConnection = nodeContext.getPeerMap().get(message.getNodeName());

            for (byte[] message : transformedMessages)
            {
                MessageReply reply = peerConnection.sendMessage(CommandMessage.Type.TRANSFER_TO_BOARD, new UploadMessage(board.getName(), message));

                if (reply.getType() != MessageReply.Type.OKAY)
                {
                    throw new ServiceConnectionException("message failed");
                }
            }
        }
        catch (ServiceConnectionException e)
        {
            // TODO: log?
        }
    }
}
