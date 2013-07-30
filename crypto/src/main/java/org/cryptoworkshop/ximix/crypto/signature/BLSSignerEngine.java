package org.cryptoworkshop.ximix.crypto.signature;

import java.math.BigInteger;
import java.util.concurrent.atomic.AtomicLong;

import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01Parameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.cryptoworkshop.ximix.common.message.BigIntegerMessage;
import org.cryptoworkshop.ximix.common.message.ElementMessage;
import org.cryptoworkshop.ximix.common.message.KeyIDMessage;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.MessageType;
import org.cryptoworkshop.ximix.common.message.ShareMessage;
import org.cryptoworkshop.ximix.common.message.SignatureMessage;
import org.cryptoworkshop.ximix.common.service.Algorithm;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.PrivateKeyOperator;
import org.cryptoworkshop.ximix.crypto.key.util.BLSPublicKeyFactory;
import org.cryptoworkshop.ximix.crypto.operator.BLSPrivateKeyOperator;
import org.cryptoworkshop.ximix.crypto.signature.message.BLSPartialCreateMessage;
import org.cryptoworkshop.ximix.crypto.signature.message.ECDSACreateMessage;
import org.cryptoworkshop.ximix.crypto.util.Participant;

public class BLSSignerEngine
    extends SignerEngine
{
    public static enum Type
        implements MessageType
    {
        GENERATE,
        INIT_K_AND_P,
        INIT_A,
        INIT_B,
        INIT_C,
        INIT_R,
        INIT_MU,
        FETCH_P,
        FETCH_MU,
        FETCH_SEQUENCE_NO,
        PRIVATE_KEY_SIGN,
        STORE_K,
        STORE_A,
        STORE_B,
        STORE_C,
        STORE_P
    }

    private final AtomicLong idCounter = new AtomicLong(1);

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
            case GENERATE:
                final ECDSACreateMessage ecdsaCreate = ECDSACreateMessage.getInstance(message.getPayload());

                //
                // if we're not one of the nominated nodes, pass it on to someone who is and send back
                // the first success response we get.
                //
                if (!ecdsaCreate.getNodesToUse().contains(nodeContext.getName()))
                {
                    for (String name : ecdsaCreate.getNodesToUse())
                    {
                        // TODO: check response status
                        return sendMessage(name, Type.GENERATE, ecdsaCreate);
                    }
                }

                Participant[] participants = new Participant[ecdsaCreate.getNodesToUse().size()];
                int index = 0;

                for (String name : ecdsaCreate.getNodesToUse())
                {
                    MessageReply seqRep = sendMessage(name, Type.FETCH_SEQUENCE_NO, new KeyIDMessage(ecdsaCreate.getKeyID()));
                    // TODO: need to drop out people who don't reply.
                    participants[index] = new Participant(BigIntegerMessage.getInstance(seqRep.getPayload()).getValue().intValue(), name);
                    index++;
                }

                SigID sigID = new SigID(nodeContext.getName() + ".BLS." + idCounter.getAndIncrement());

                SubjectPublicKeyInfo pubKeyInfo = nodeContext.getPublicKey(ecdsaCreate.getKeyID());
                BLS01Parameters domainParams = BLSPublicKeyFactory.createKey(pubKeyInfo).getParameters();
                Pairing pairing = PairingFactory.getInstance().getPairing(domainParams.getCurveParameters());

                byte[] hash = ecdsaCreate.getMessage();
                Element h = pairing.getG1().newElement().setFromHash(hash, 0, hash.length);

                // TODO: need to take into account node failure during startup.
                Element signature = accumulateElement(participants, Type.PRIVATE_KEY_SIGN, new BLSPartialCreateMessage(sigID.getID(), ecdsaCreate.getKeyID(), h, participants), pairing, pairing.getZr().getOrder());

                signature = signature.powZn(pairing.getZr().newOneElement());

                return new MessageReply(MessageReply.Type.OKAY, new DEROctetString(signature.toBytes()));
            case FETCH_SEQUENCE_NO:
                KeyIDMessage keyIDMessage = KeyIDMessage.getInstance(message.getPayload());

                return new MessageReply(MessageReply.Type.OKAY, new BigIntegerMessage(BigInteger.valueOf(nodeContext.getPrivateKeyOperator(keyIDMessage.getKeyID()).getSequenceNo())));
            case PRIVATE_KEY_SIGN:
                BLSPartialCreateMessage partialMessage = BLSPartialCreateMessage.getInstance(message.getPayload());

                pubKeyInfo = nodeContext.getPublicKey(partialMessage.getKeyID());
                domainParams = BLSPublicKeyFactory.createKey(pubKeyInfo).getParameters();
                pairing = PairingFactory.getInstance().getPairing(domainParams.getCurveParameters());


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
