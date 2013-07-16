package org.cryptoworkshop.ximix.crypto.signature.message;

import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.Set;
import java.util.TreeSet;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;
import org.cryptoworkshop.ximix.common.message.ParticipantMessage;
import org.cryptoworkshop.ximix.crypto.util.Participant;

class MessageUtils
{
    static Set<String> toOrderedSet(String[] nodes)
    {
        Set<String> orderedSet = new TreeSet(new CaseInsensitiveComparator());

        for (String node : nodes)
        {
            orderedSet.add(node);
        }

        return Collections.unmodifiableSet(orderedSet);
    }

    static Set<String> toOrderedSet(ASN1Sequence set)
    {
        Set<String> orderedSet = new TreeSet(new CaseInsensitiveComparator());

        for (Enumeration en = set.getObjects(); en.hasMoreElements();)
        {
            orderedSet.add(DERUTF8String.getInstance(en.nextElement()).getString());
        }

        return Collections.unmodifiableSet(orderedSet);
    }

    static ASN1Sequence toASN1Sequence(Set<String> set)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (String name : set)
        {
            v.add(new DERUTF8String(name));
        }

        return new DLSequence(v);
    }

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

    private static class CaseInsensitiveComparator
        implements Comparator<String>
    {
        @Override
        public int compare(String s1, String s2)
        {
            return s1.compareToIgnoreCase(s2);
        }
    }
}
