package org.cryptoworkshop.ximix.tool;

import java.io.FileOutputStream;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * basic class to generate a trust anchor, with an associated key store.
 */
public class GenTrustAnchorKeyStore
{
    private static final long YEAR = 1000 * 60 * 60 * 24 * 365;

    public static void main(String[] args)
        throws Exception
    {
        if (args.length != 2)
        {
            System.err.println("Usage: GenTrustAnchorKeyStore keyStoreName keyStorePassword");
            System.exit(1);
        }

        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECDSA", "BC");

        kpGen.initialize(new ECNamedCurveGenParameterSpec("secp256r1"));

        KeyPair kp = kpGen.generateKeyPair();

        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

        builder.addRDN(BCStyle.C, "AU");
        builder.addRDN(BCStyle.O, "Crypto Workshop Pty Ltd");
        builder.addRDN(BCStyle.OU, "Ximix Node Test CA");
        builder.addRDN(BCStyle.L, "Melbourne");
        builder.addRDN(BCStyle.ST, "Victoria");
        builder.addRDN(BCStyle.CN, "Trust Anchor");

        Date startDate = new Date(System.currentTimeMillis() - 50000);

        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(kp.getPrivate());
        X509v1CertificateBuilder certGen1 = new JcaX509v1CertificateBuilder(builder.build(), BigInteger.valueOf(1), startDate, new Date(System.currentTimeMillis() + YEAR),builder.build(), kp.getPublic());

        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen1.build(sigGen));

        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");

        keyStore.load(null, null);

        keyStore.setKeyEntry("trust", kp.getPrivate(), null, new Certificate[] { cert });

        keyStore.store(new FileOutputStream(args[0] + ".p12"), args[1].toCharArray());

        PEMWriter pWrt = new PEMWriter(new FileWriter(args[0] + ".pem"));

        pWrt.writeObject(cert);

        pWrt.close();
    }
}
