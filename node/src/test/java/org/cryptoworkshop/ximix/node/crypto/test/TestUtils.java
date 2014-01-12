package org.cryptoworkshop.ximix.node.crypto.test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;

public class TestUtils
{
    private static final long YEAR = 1000 * 60 * 60 * 24 * 365;

    static KeyStore genCAKeyStore(String nodeName)
    {
        try
        {
            KeyFactory fact = KeyFactory.getInstance("ECDSA", "BC");

            EllipticCurve curve = new EllipticCurve(
                new ECFieldFp(new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839")), // q
                new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
                new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

            ECParameterSpec spec = new ECParameterSpec(
                curve,
                ECPointUtil.decodePoint(curve, Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
                new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"), // n
                1); // h


            ECPrivateKeySpec priKeySpec = new ECPrivateKeySpec(
                new BigInteger("876300101507107567501066130761671078357010671067781776716671676178726717"), // d
                spec);

            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(
                ECPointUtil.decodePoint(curve, Hex.decode("025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70")), // Q
                spec);

            PrivateKey sigKey = fact.generatePrivate(priKeySpec);
            PublicKey pubKey = fact.generatePublic(pubKeySpec);

            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");

            ks.load(null, null);

            X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

            builder.addRDN(BCStyle.C, "AU");
            builder.addRDN(BCStyle.O, "Crypto Workshop Pty Ltd");
            builder.addRDN(BCStyle.OU, "Ximix Node Test CA");
            builder.addRDN(BCStyle.L, "Melbourne");
            builder.addRDN(BCStyle.ST, "Victoria");
            builder.addRDN(BCStyle.CN, nodeName);

            Date startDate = new Date(System.currentTimeMillis() - 50000);

            ContentSigner sigGen = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(sigKey);
            X509v1CertificateBuilder certGen1 = new JcaX509v1CertificateBuilder(builder.build(), BigInteger.valueOf(1), startDate, new Date(System.currentTimeMillis() + YEAR), builder.build(), pubKey);

            X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen1.build(sigGen));

            ks.setKeyEntry("nodeCA", sigKey, new char[0], new Certificate[]{cert});

            return ks;
        }
        catch (Exception e)
        {
            throw new IllegalStateException("unable to set up test CA", e);
        }
    }
}
