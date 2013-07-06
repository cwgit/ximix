package org.cryptoworkshop.ximix.crypto.signature;

import java.math.BigInteger;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.ASN1Encodable;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.SignatureMessage;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.common.message.BigIntegerMessage;
import org.cryptoworkshop.ximix.crypto.threshold.LagrangeWeightCalculator;

public abstract class SignerEngine
{
    protected final int algorithm;
    protected final NodeContext nodeContext;

    protected SignerEngine(int algorithm, NodeContext nodeContext)
    {
        this.algorithm = algorithm;
        this.nodeContext = nodeContext;
    }

    public int getAlgorithm()
    {
        return algorithm;
    }

    protected MessageReply sendMessage(String node, Enum type, ASN1Encodable message)
        throws ServiceConnectionException
    {
        if (node.equals(nodeContext.getName()))
        {
            return handle(new SignatureMessage(algorithm, type, message));
        }
        else
        {
            return nodeContext.getPeerMap().get(node).sendMessage(CommandMessage.Type.SIGNATURE_MESSAGE, new SignatureMessage(algorithm, type, message));
        }
    }

    protected MessageReply broadcastMessage(Set<String> peers, Enum type, ASN1Encodable message)
        throws ServiceConnectionException
    {
        for (String node : peers)
        {
            return nodeContext.getPeerMap().get(node).sendMessage(CommandMessage.Type.SIGNATURE_MESSAGE, new SignatureMessage(algorithm, type, message));
        }
        // TODO: build composite reply.
        return null;
    }

    protected MessageReply replyOkay(ASN1Encodable payload)
    {
        return new MessageReply(MessageReply.Type.OKAY, payload);
    }

    protected BigInteger accumulateBigInt(Set<String> nodes, Enum fetchOperatorType, ASN1Encodable request, BigInteger fieldSize)
        throws ServiceConnectionException
    {
        BigInteger[] valueShares = new BigInteger[nodes.size()];
        LagrangeWeightCalculator calculator = new LagrangeWeightCalculator(valueShares.length, fieldSize);

        int counter = 0;
        MessageReply[] replys = new MessageReply[nodes.size()];
        for (String nodeName : nodes)
        {
            replys[counter++] = sendMessage(nodeName, fetchOperatorType, request);
        }

        for (int i = 0; i != replys.length; i++)
        {
            if (replys[i] == null || replys[i].getType() != MessageReply.Type.OKAY)
            {
                valueShares[i] = null;
            }
            else
            {
                valueShares[i] = BigIntegerMessage.getInstance(replys[i].getPayload()).getValue();
            }
        }

        BigInteger[] weights = calculator.computeWeights(valueShares);
        // weighting
        BigInteger value = valueShares[0].multiply(weights[0]);
        for (int i = 1; i < weights.length; i++)
        {
            if (valueShares[i] != null)
            {
                value = value.add(valueShares[i].multiply(weights[i])).mod(fieldSize);
            }
        }

        return value;
    }

    void execute(Runnable task)
    {
        nodeContext.execute(task);
    }

    void schedule(Runnable task, long time, TimeUnit timeUnit)
    {
        nodeContext.schedule(task, time, timeUnit);
    }

    public abstract MessageReply handle(SignatureMessage signatureMessage);

}
