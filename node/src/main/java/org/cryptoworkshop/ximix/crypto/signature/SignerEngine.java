package org.cryptoworkshop.ximix.crypto.signature;

import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.common.asn1.message.AlgorithmServiceMessage;
import org.cryptoworkshop.ximix.common.asn1.message.BigIntegerMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CommandMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ECPointMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ElementMessage;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.ShareMessage;
import org.cryptoworkshop.ximix.common.asn1.message.SignatureMessage;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.crypto.threshold.LagrangeWeightCalculator;
import org.cryptoworkshop.ximix.crypto.util.Participant;
import org.cryptoworkshop.ximix.node.service.NodeContext;

public abstract class SignerEngine
{
    protected final Algorithm algorithm;
    protected final NodeContext nodeContext;

    protected SignerEngine(Algorithm algorithm, NodeContext nodeContext)
    {
        this.algorithm = algorithm;
        this.nodeContext = nodeContext;
    }

    public Algorithm getAlgorithm()
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
            return nodeContext.getPeerMap().get(node).sendMessage(CommandMessage.Type.SIGNATURE_MESSAGE, new AlgorithmServiceMessage(getAlgorithm(), new SignatureMessage(algorithm, type, message)));
        }
    }

    protected MessageReply replyOkay(ASN1Encodable payload)
    {
        return new MessageReply(MessageReply.Type.OKAY, payload);
    }

    protected BigInteger accumulateBigInteger(Participant[] nodes, Enum fetchOperatorType, ASN1Encodable request, BigInteger fieldSize)
        throws ServiceConnectionException
    {
        ASN1Encodable[] valueShares = getShareData(nodes, fetchOperatorType, request);

        //
        // we don't need to know how many peers, just the maximum index (max(sequenceNo) + 1) of the one available
        //
        LagrangeWeightCalculator calculator = new LagrangeWeightCalculator(valueShares.length, fieldSize);

        BigInteger[] weights = calculator.computeWeights(valueShares);

        int baseIndex = getBaseIndex(valueShares);

        BigInteger     baseValue = BigIntegerMessage.getInstance(valueShares[baseIndex]).getValue();
        BigInteger     baseWeight = weights[baseIndex];

        // weighting
        BigInteger value = baseValue.multiply(baseWeight);
        for (int i = baseIndex + 1; i < weights.length; i++)
        {
            if (valueShares[i] != null)
            {
                value = value.add(BigIntegerMessage.getInstance(valueShares[i]).getValue().multiply(weights[i])).mod(fieldSize);
            }
        }

        return value;
    }

    protected ECPoint accumulateECPoint(Participant[] nodes, Enum fetchOperatorType, ASN1Encodable request, ECCurve curve, BigInteger fieldSize)
        throws ServiceConnectionException
    {
        ASN1Encodable[] valueShares = getShareData(nodes, fetchOperatorType, request);

        //
        // we don't need to know how many peers, just the maximum index (max(sequenceNo) + 1) of the one available
        //
        LagrangeWeightCalculator calculator = new LagrangeWeightCalculator(valueShares.length, fieldSize);

        BigInteger[] weights = calculator.computeWeights(valueShares);

        int baseIndex = getBaseIndex(valueShares);

        ECPoint baseValue = ECPointMessage.getInstance(curve, valueShares[baseIndex]).getPoint();
        BigInteger baseWeight = weights[baseIndex];

        // weighting
        ECPoint value = baseValue.multiply(baseWeight);
        for (int i = baseIndex + 1; i < weights.length; i++)
        {
            if (valueShares[i] != null)
            {
                value = value.add(ECPointMessage.getInstance(curve, valueShares[i]).getPoint().multiply(weights[i]));
            }
        }

        return value;
    }

    protected Element accumulateElement(Participant[] nodes, Enum fetchOperatorType, ASN1Encodable request, Pairing pairing, BigInteger fieldSize)
        throws ServiceConnectionException
    {
        ASN1Encodable[] valueShares = getShareData(nodes, fetchOperatorType, request);

        //
        // we don't need to know how many peers, just the maximum index (max(sequenceNo) + 1) of the one available
        //
        LagrangeWeightCalculator calculator = new LagrangeWeightCalculator(valueShares.length, fieldSize);

        BigInteger[] weights = calculator.computeWeights(valueShares);

        int baseIndex = getBaseIndex(valueShares);

        Element        baseValue = ElementMessage.getInstance(pairing, valueShares[baseIndex]).getValue();
        BigInteger     baseWeight = weights[baseIndex];

        // weighting
        Element value = baseValue.powZn(pairing.getZr().newElement(baseWeight));
        for (int i = baseIndex + 1; i < weights.length; i++)
        {
            if (valueShares[i] != null)
            {
                value = value.mul(ElementMessage.getInstance(pairing, valueShares[i]).getValue().powZn(pairing.getZr().newElement(weights[i])));
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

    /**
     * Find the first non-null element in a share array.
     *
     * @param valueShares  share array to examine
     * @return the index of the first non-null element.
     */
    private int getBaseIndex(ASN1Encodable[] valueShares)
    {
        int  baseIndex = 0;
        for (int i = 0; i != valueShares.length; i++)
        {
            if (valueShares[i] != null)
            {
                baseIndex = i;
                break;
            }
        }
        return baseIndex;
    }

    /**
     * Return a properly distributed list of shares with null values occupying any gaps.
     *
     * @throws ServiceConnectionException
     */
    private ASN1Encodable[] getShareData(Participant[] nodes, Enum fetchOperatorType, ASN1Encodable request)
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

        ASN1Encodable[] valueShares = new ASN1Encodable[maxSequenceNo + 1];

        for (int i = 0; i != shareMessages.length; i++)
        {
            ShareMessage shareMsg = shareMessages[i];

            valueShares[shareMsg.getSequenceNo()] = shareMsg.getShareData();
        }

        return valueShares;
    }

    public abstract MessageReply handle(SignatureMessage signatureMessage);

}
