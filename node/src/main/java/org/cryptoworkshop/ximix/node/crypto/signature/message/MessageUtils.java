package org.cryptoworkshop.ximix.node.crypto.signature.message;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DLSequence;
import org.cryptoworkshop.ximix.common.asn1.message.ParticipantMessage;
import org.cryptoworkshop.ximix.node.crypto.util.Participant;

class MessageUtils
{


    static ASN1Sequence toASN1Sequence(Participant[] participants)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (Participant participant : participants)
        {
            v.add(new ParticipantMessage(participant.getSequenceNo(), participant.getName()));
        }

        return new DLSequence(v);
    }

    public static Participant[] toArray(ASN1Sequence seq)
    {
        Participant[] participants = new Participant[seq.size()];

        for (int i = 0; i != participants.length; i++)
        {
            ParticipantMessage pm = ParticipantMessage.getInstance(seq.getObjectAt(i));

            participants[i] = new Participant(pm.getSequenceNo(), pm.getName());
        }

        return participants;
    }


}
