package org.cryptoworkshop.ximix.tool;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * basic class to generate a key store file for a nodes CA.
 */
public class GenNodeKeyStore
{
    private static final long YEAR = 1000 * 60 * 60 * 24 * 365;

    public static void main(String[] args)
        throws Exception
    {
        if (args.length != 5)
        {
            System.err.println("Usage: GenNodeKeyStore nodeName trustAnchorKeyStore trustAnchorPassword keyStoreName keyStorePassword");
            System.exit(1);
        }

        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECDSA", "BC");

        kpGen.initialize(new ECNamedCurveGenParameterSpec("secp256r1"));

        KeyPair kp = kpGen.generateKeyPair();

        KeyStore trustStore = KeyStore.getInstance("PKCS12", "BC");

        trustStore.load(new FileInputStream(args[1] + ".p12"), args[2].toCharArray());

        X509Certificate trustCert = (X509Certificate)trustStore.getCertificate("trust");
        PrivateKey      privKey = (PrivateKey)trustStore.getKey("trust", null);

        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

        builder.addRDN(BCStyle.C, "AU");
        builder.addRDN(BCStyle.O, "Crypto Workshop Pty Ltd");
        builder.addRDN(BCStyle.OU, "Ximix Node Test CA");
        builder.addRDN(BCStyle.L, "Melbourne");
        builder.addRDN(BCStyle.ST, "Victoria");
        builder.addRDN(BCStyle.CN, args[0]);

        Date startDate = new Date(System.currentTimeMillis() - 50000);

        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(privKey);

        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils(new SHA1DigestCalculator());
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
            X500Name.getInstance(trustCert.getSubjectX500Principal().getEncoded()),
            BigInteger.valueOf(System.currentTimeMillis()),
            startDate, new Date(System.currentTimeMillis() + YEAR),
            builder.build(), kp.getPublic());

        certGen.addExtension(Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(kp.getPublic()));
        certGen.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(trustCert));

        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(sigGen));

        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");

        keyStore.load(null, null);

        keyStore.setKeyEntry("nodeCA", kp.getPrivate(), null, new Certificate[] { cert });

        keyStore.store(new FileOutputStream(args[3] + ".p12"), args[4].toCharArray());
    }
}
