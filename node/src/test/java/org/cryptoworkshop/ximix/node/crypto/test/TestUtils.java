package org.cryptoworkshop.ximix.node.crypto.test;

import java.io.File;
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
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.cryptoworkshop.ximix.client.connection.ServicesConnection;
import org.cryptoworkshop.ximix.common.asn1.PartialPublicKeyInfo;
import org.cryptoworkshop.ximix.common.asn1.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.common.util.EventNotifier;
import org.cryptoworkshop.ximix.node.service.Decoupler;
import org.cryptoworkshop.ximix.node.service.ListeningSocketInfo;
import org.cryptoworkshop.ximix.node.service.NodeContext;
import org.cryptoworkshop.ximix.node.service.NodeService;
import org.cryptoworkshop.ximix.node.service.PrivateKeyOperator;
import org.cryptoworkshop.ximix.node.service.ThresholdKeyPairGenerator;

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

    static class BasicNodeContext
         implements NodeContext
     {
         private final String name;

         private ScheduledExecutorService scheduledExecutorService = Executors.newScheduledThreadPool(10);

         BasicNodeContext(String name)
         {
             this.name = name;
         }
         @Override
         public String getName()
         {
             return name;
         }

         @Override
         public Map<String, ServicesConnection> getPeerMap()
         {
             return null;  //To change body of implemented methods use File | Settings | File Templates.
         }

         @Override
         public CapabilityMessage[] getCapabilities()
         {
             return new CapabilityMessage[0];
         }

         @Override
         public SubjectPublicKeyInfo getPublicKey(String keyID)
         {
             return null;  //To change body of implemented methods use File | Settings | File Templates.
         }

         @Override
         public boolean hasPrivateKey(String keyID)
         {
             return false;  //To change body of implemented methods use File | Settings | File Templates.
         }

         @Override
         public PartialPublicKeyInfo getPartialPublicKey(String keyID)
         {
             return null;  //To change body of implemented methods use File | Settings | File Templates.
         }

         @Override
         public PrivateKeyOperator getPrivateKeyOperator(String keyID)
         {
             return null;  //To change body of implemented methods use File | Settings | File Templates.
         }

         @Override
         public boolean shutdown(int time, TimeUnit timeUnit)
             throws InterruptedException
         {
             scheduledExecutorService.shutdown();

             return true;
         }

         @Override
         public boolean isStopCalled()
         {
             return false;  //To change body of implemented methods use File | Settings | File Templates.
         }

         @Override
         public void execute(Runnable task)
         {
             scheduledExecutorService.execute(task);
         }

         @Override
         public void schedule(Runnable task, long time, TimeUnit timeUnit)
         {
             scheduledExecutorService.schedule(task, time, TimeUnit.SECONDS);
         }

         @Override
         public Executor getDecoupler(Decoupler task)
         {
             return Executors.newSingleThreadExecutor();
         }

         @Override
         public ScheduledExecutorService getScheduledExecutorService()
         {
             return scheduledExecutorService;
         }

         @Override
         public ThresholdKeyPairGenerator getKeyPairGenerator(Algorithm algorithm)
         {
             return null;  //To change body of implemented methods use File | Settings | File Templates.
         }

         @Override
         public KeyStore getNodeCAStore()
         {
             return TestUtils.genCAKeyStore(name);
         }

         @Override
         public String getBoardHost(String boardName)
         {
             return null;  //To change body of implemented methods use File | Settings | File Templates.
         }

         @Override
         public File getHomeDirectory()
         {
             return null;  //To change body of implemented methods use File | Settings | File Templates.
         }

         @Override
         public Map<NodeService, Map<String, Object>> getServiceStatistics()
         {
             return null;  //To change body of implemented methods use File | Settings | File Templates.
         }

         @Override
         public Map<String, String> getDescription()
         {
             return null;  //To change body of implemented methods use File | Settings | File Templates.
         }

         @Override
         public ListeningSocketInfo getListeningSocketInfo()
         {
             return null;  //To change body of implemented methods use File | Settings | File Templates.
         }


         @Override
         public EventNotifier getEventNotifier()
         {

             return new TestNotifier();
         }

         @Override
         public X509Certificate getTrustAnchor()
         {
             return null;
         }

         @Override
         public ExecutorService getExecutorService()
         {
             return getScheduledExecutorService();
         }
     }
}
