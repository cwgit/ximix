package org.cryptoworkshop.ximix.crypto.signature;

import java.math.BigInteger;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.common.message.BigIntegerMessage;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.ECPointMessage;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.ShareMessage;
import org.cryptoworkshop.ximix.common.message.SignatureMessage;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.crypto.threshold.LagrangeWeightCalculator;
import org.cryptoworkshop.ximix.crypto.util.Participant;

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

    protected BigInteger accumulateBigInteger(Participant[] nodes, Enum fetchOperatorType, ASN1Encodable request, BigInteger fieldSize)
        throws ServiceConnectionException
    {
        MessageReply[] replys = new MessageReply[nodes.length];

        // TODO: deal with drop outs
        int count = 0;
        while (count != nodes.length)
        {
            replys[count] = sendMessage(nodes[count].getName(), fetchOperatorType, request);
            if (replys[count].getType() != MessageReply.Type.OKAY)
            {
                                 // TODO: maybe log
                replys[count] = null;
            }
            count++;
        }

        ShareMessage[] shareMessages = new ShareMessage[nodes.length];
        int            maxSequenceNo = 0;

        for (int i = 0; i != shareMessages.length; i++)
        {
            shareMessages[i] = ShareMessage.getInstance(replys[i].getPayload());
            if (maxSequenceNo < shareMessages[i].getSequenceNo())
            {
                maxSequenceNo = shareMessages[i].getSequenceNo();
            }
        }

        BigInteger[] valueShares = new BigInteger[maxSequenceNo + 1];

        for (int i = 0; i != shareMessages.length; i++)
        {
            ShareMessage shareMsg = shareMessages[i];

            valueShares[shareMsg.getSequenceNo()] = BigIntegerMessage.getInstance(shareMsg.getShareData()).getValue();
        }

        //
        // we don't need to know how many peers, just the maximum index (maxSequenceNo + 1) of the one available
        //
        LagrangeWeightCalculator calculator = new LagrangeWeightCalculator(maxSequenceNo + 1, fieldSize);

        BigInteger[] weights = calculator.computeWeights(valueShares);

        int            baseIndex = 0;
        for (int i = 0; i != valueShares.length; i++)
        {
            if (valueShares[i] != null)
            {
                baseIndex = i;
                break;
            }
        }

        BigInteger     baseValue = valueShares[baseIndex];
        BigInteger     baseWeight = weights[baseIndex];

        // weighting
        BigInteger value = baseValue.multiply(baseWeight);
        for (int i = baseIndex + 1; i < weights.length; i++)
        {
            if (valueShares[i] != null)
            {
                value = value.add(valueShares[i].multiply(weights[i])).mod(fieldSize);
            }
        }

        return value;
    }

    protected ECPoint accumulateECPoint(Participant[] nodes, Enum fetchOperatorType, ASN1Encodable request, ECCurve curve, BigInteger fieldSize)
         throws ServiceConnectionException
     {
         MessageReply[] replys = new MessageReply[nodes.length];

         // TODO: deal with drop outs
         int count = 0;
         while (count != nodes.length)
         {
             replys[count] = sendMessage(nodes[count].getName(), fetchOperatorType, request);
             if (replys[count].getType() != MessageReply.Type.OKAY)
             {
                                  // TODO: maybe log
                 replys[count] = null;
             }
             count++;
         }

         ShareMessage[] shareMessages = new ShareMessage[nodes.length];
         int            maxSequenceNo = 0;

         for (int i = 0; i != shareMessages.length; i++)
         {
             shareMessages[i] = ShareMessage.getInstance(replys[i].getPayload());
             if (maxSequenceNo < shareMessages[i].getSequenceNo())
             {
                 maxSequenceNo = shareMessages[i].getSequenceNo();
             }
         }

         ECPoint[] valueShares = new ECPoint[maxSequenceNo + 1];

         for (int i = 0; i != shareMessages.length; i++)
         {
             ShareMessage shareMsg = shareMessages[i];

             valueShares[shareMsg.getSequenceNo()] = ECPointMessage.getInstance(curve, shareMsg.getShareData()).getPoint();
         }

         //
         // we don't need to know how many peers, just the maximum index (maxSequenceNo + 1) of the one available
         //
         LagrangeWeightCalculator calculator = new LagrangeWeightCalculator(maxSequenceNo + 1, fieldSize);

         BigInteger[] weights = calculator.computeWeights(valueShares);

         int            baseIndex = 0;
         for (int i = 0; i != valueShares.length; i++)
         {
             if (valueShares[i] != null)
             {
                 baseIndex = i;
                 break;
             }
         }

         ECPoint        baseValue = valueShares[baseIndex];
         BigInteger     baseWeight = weights[baseIndex];

         // weighting
         ECPoint value = baseValue.multiply(baseWeight);
         for (int i = baseIndex + 1; i < weights.length; i++)
         {
             if (valueShares[i] != null)
             {
                 value = value.add(valueShares[i].multiply(weights[i]));
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
