package org.cryptoworkshop.ximix.node.crypto.signature;

import java.math.BigInteger;
import java.util.concurrent.atomic.AtomicLong;

import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01Parameters;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.cryptoworkshop.ximix.client.connection.signing.BLSSigningService.Type;
import org.cryptoworkshop.ximix.client.connection.signing.message.BLSPartialCreateMessage;
import org.cryptoworkshop.ximix.common.asn1.message.BigIntegerMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ElementMessage;
import org.cryptoworkshop.ximix.common.asn1.message.KeyIDMessage;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.ShareMessage;
import org.cryptoworkshop.ximix.common.asn1.message.SignatureMessage;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.node.crypto.key.util.BLSPublicKeyFactory;
import org.cryptoworkshop.ximix.node.crypto.operator.BLSPrivateKeyOperator;
import org.cryptoworkshop.ximix.node.service.NodeContext;
import org.cryptoworkshop.ximix.node.service.PrivateKeyOperator;

/**
 * Engine class for generating threshold BLS signatures.
 */
public class BLSSignerEngine
    extends SignerEngine
{
    private final AtomicLong idCounter = new AtomicLong(1);

    /**
     * Base constructor.
     *
     * @param nodeContext the context for the node we are associated with.
     */
    public BLSSignerEngine(NodeContext nodeContext)
    {
        super(Algorithm.BLS, nodeContext);
    }

    public MessageReply handle(SignatureMessage message)
    {
        try
        {
            switch ((Type)message.getType())
            {
            case FETCH_SEQUENCE_NO:     // TODO: for BLS this may not actually be required.
                KeyIDMessage keyIDMessage = KeyIDMessage.getInstance(message.getPayload());

                return new MessageReply(MessageReply.Type.OKAY, new BigIntegerMessage(BigInteger.valueOf(nodeContext.getPrivateKeyOperator(keyIDMessage.getKeyID()).getSequenceNo())));
            case PRIVATE_KEY_SIGN:
                BLSPartialCreateMessage partialMessage = BLSPartialCreateMessage.getInstance(message.getPayload());

                SubjectPublicKeyInfo pubKeyInfo = nodeContext.getPublicKey(partialMessage.getKeyID());
                BLS01Parameters domainParams = BLSPublicKeyFactory.createKey(pubKeyInfo).getParameters();
                Pairing pairing = PairingFactory.getInstance().getPairing(domainParams.getCurveParameters());

                PrivateKeyOperator operator = nodeContext.getPrivateKeyOperator(partialMessage.getKeyID());

                if (!(operator instanceof BLSPrivateKeyOperator))
                {
                    return new MessageReply(MessageReply.Type.ERROR); // TODO
                }

                BLSPrivateKeyOperator blsOperator = (BLSPrivateKeyOperator)operator;

                MessageReply reply = replyOkay(new ShareMessage(blsOperator.getSequenceNo(), new ElementMessage(blsOperator.transform(partialMessage.getH(pairing)))));
                // TODO: need to clean up state tables here.
                return reply;
            default:
                return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Unknown command in NodeSigningService."));
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("NodeKeyGenerationService failure: " + e.getMessage()));
        }
    }
}
