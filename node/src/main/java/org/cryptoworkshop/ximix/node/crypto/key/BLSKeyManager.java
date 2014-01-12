/**
 * Copyright 2013 Crypto Workshop Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.cryptoworkshop.ximix.node.crypto.key;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import it.unisa.dia.gas.crypto.jpbc.signature.bls01.generators.BLS01KeyPairGenerator;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01KeyGenerationParameters;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01Parameters;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01PublicKeyParameters;
import it.unisa.dia.gas.jpbc.CurveParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.DefaultCurveParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBagFactory;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.bouncycastle.util.Strings;
import org.cryptoworkshop.ximix.common.asn1.PartialPublicKeyInfo;
import org.cryptoworkshop.ximix.common.asn1.XimixObjectIdentifiers;
import org.cryptoworkshop.ximix.common.asn1.message.NamedKeyGenParams;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.common.crypto.threshold.BLSCommittedSecretShare;
import org.cryptoworkshop.ximix.common.util.DecoupledListenerHandlerFactory;
import org.cryptoworkshop.ximix.common.util.ListenerHandler;
import org.cryptoworkshop.ximix.node.crypto.key.message.BLSCommittedSecretShareMessage;
import org.cryptoworkshop.ximix.node.crypto.key.util.BLSPublicKeyFactory;
import org.cryptoworkshop.ximix.node.crypto.key.util.PrivateKeyInfoFactory;
import org.cryptoworkshop.ximix.node.crypto.key.util.SubjectPublicKeyInfoFactory;
import org.cryptoworkshop.ximix.node.crypto.operator.jpbc.JpbcPrivateKeyOperator;
import org.cryptoworkshop.ximix.node.crypto.util.BigIntegerShare;
import org.cryptoworkshop.ximix.node.crypto.util.ElementShare;
import org.cryptoworkshop.ximix.node.crypto.util.Share;
import org.cryptoworkshop.ximix.node.crypto.util.ShareMap;
import org.cryptoworkshop.ximix.node.crypto.util.ShareMapListener;
import org.cryptoworkshop.ximix.node.service.Decoupler;
import org.cryptoworkshop.ximix.node.service.NodeContext;
import org.cryptoworkshop.ximix.node.service.PrivateKeyOperator;

/**
 * A manager for BLS keys stored in a node.
 */
public class BLSKeyManager
    implements KeyManager
{
    private static final int TIME_OUT = 20;

    private final Map<String, BLS01Parameters> paramsMap = new HashMap<>();
    private final Map<String, BigInteger> hMap = new HashMap<>();
    private final Set<String> signingKeys = new HashSet<>();
    private final ShareMap<String, BigInteger> sharedPrivateKeyMap;
    private final ShareMap<String, Element> sharedPublicKeyMap;
    private final NodeContext nodeContext;
    private final ListenerHandler<KeyManagerListener> listenerHandler;
    private final KeyManagerListener notifier;

    /**
     * Base constructor.
     *
     * @param nodeContext the node context this manager is associated with.
     */
    public BLSKeyManager(NodeContext nodeContext)
    {
        this.nodeContext = nodeContext;
        this.listenerHandler = new DecoupledListenerHandlerFactory(nodeContext.getDecoupler(Decoupler.LISTENER), nodeContext.getEventNotifier()).createHandler(KeyManagerListener.class);
        this.notifier = listenerHandler.getNotifier();

        sharedPublicKeyMap = new ShareMap<>(nodeContext.getScheduledExecutorService(), nodeContext.getDecoupler(Decoupler.SHARING), nodeContext.getEventNotifier());
        sharedPrivateKeyMap = new ShareMap<>(nodeContext.getScheduledExecutorService(), nodeContext.getDecoupler(Decoupler.SHARING), nodeContext.getEventNotifier());

        sharedPrivateKeyMap.addListener(new ShareMapListener<String, BigInteger>()
        {
            @Override
            public void shareCompleted(ShareMap<String, BigInteger> shareMap, String id)
            {
                notifier.keyAdded(BLSKeyManager.this, id);
            }
        });
    }

    @Override
    public String getID()
    {
        return "BLS";
    }

    @Override
    public synchronized boolean hasPrivateKey(String keyID)
    {
        return sharedPrivateKeyMap.containsKey(keyID);
    }

    @Override
    public synchronized boolean isSigningKey(String keyID)
    {
        return true;
    }

    public BLS01Parameters getParams(String keyID)
    {
        return paramsMap.get(keyID);
    }

    public synchronized AsymmetricCipherKeyPair generateKeyPair(String keyID, Algorithm algorithm, int numberOfPeers, NamedKeyGenParams keyGenParams)
    {
        BLS01Parameters domainParameters = paramsMap.get(keyID);

        if (domainParameters == null)
        {
            BLS01KeyPairGenerator kpGen = new BLS01KeyPairGenerator();
            CurveParameters       curveParameters = new DefaultCurveParameters().load(this.getClass().getResourceAsStream("d62003-159-158.param"));
            Random                random = new Random(makeSeed(Strings.toByteArray(keyID)));           // Need a consistent random... TODO: maybe a better way
            Pairing               pairing = PairingFactory.getInstance().getPairing(curveParameters, random);
            Element               g = pairing.getG2().newRandomElement();

            // we have to do this as the JPBC library ignores the random number generator passed in as
            // a parameter.
            // TODO: need to sort out source of randomness.
            random = new SecureRandom();
            pairing = PairingFactory.getInstance().getPairing(curveParameters, random);

            BLS01Parameters       blsParameters = new BLS01Parameters(curveParameters, g.getImmutable());

            kpGen.init(new BLS01KeyGenerationParameters((SecureRandom)random, blsParameters));

            AsymmetricCipherKeyPair kp =  kpGen.generateKeyPair();

            sharedPrivateKeyMap.init(keyID, numberOfPeers);
            sharedPublicKeyMap.init(keyID, numberOfPeers);

            hMap.put(keyID, keyGenParams.getH());
            paramsMap.put(keyID, blsParameters);

            return kp;
        }
        else
        {
            throw new IllegalStateException("Key " + keyID + " already exists.");
        }
    }

    @Override
    public SubjectPublicKeyInfo fetchPublicKey(String keyID)
        throws IOException
    {
        if (sharedPublicKeyMap.containsKey(keyID))
        {
            Share<Element> share = sharedPublicKeyMap.getShare(keyID, TIME_OUT, TimeUnit.SECONDS);

            if (share != null)
            {
                Element pK = share.getValue();
                BLS01Parameters params = paramsMap.get(keyID);

                return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(new BLS01PublicKeyParameters(params, pK));
            }
        }

        return null;
    }

    @Override
    public PartialPublicKeyInfo fetchPartialPublicKey(String keyID)
        throws IOException
    {
        if (sharedPrivateKeyMap.containsKey(keyID))
        {
            BLS01Parameters params = paramsMap.get(keyID);
            Share<BigInteger> share = sharedPrivateKeyMap.getShare(keyID, TIME_OUT, TimeUnit.SECONDS);
            Pairing pairing = PairingFactory.getPairing(params.getCurveParameters());
            Element g = params.getG();

            // calculate the public key
            Element sk = pairing.getZr().newElement(share.getValue());
            Element pk = g.powZn(sk);

            return new PartialPublicKeyInfo(share.getSequenceNo(), SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(new BLS01PublicKeyParameters(params, pk.getImmutable())));
        }

        return null;
    }

    public synchronized void buildSharedKey(String keyID, BLSCommittedSecretShareMessage message)
    {
        BLS01Parameters domainParams = paramsMap.get(keyID);
        BLSCommittedSecretShare share = new BLSCommittedSecretShare(message.getValue(), message.getWitness(), message.getCommitmentFactors());

        // TODO: need to be able to do this to verify key generation.
//        if (share.isRevealed(message.getIndex(), domainParams, hMap.get(keyID)))
//        {
            sharedPrivateKeyMap.addValue(keyID, new BigIntegerShare(message.getIndex(), message.getValue()));
            sharedPublicKeyMap.addValue(keyID, new ElementShare(message.getIndex(), message.getPk()));

//        }
//        else
//        {
//            throw new IllegalStateException("Commitment for " + keyID + " failed!");
//        }
    }

    public BigInteger getPartialPrivateKey(String keyID)
    {
        return sharedPrivateKeyMap.getShare(keyID).getValue();
    }

    public synchronized byte[] getEncoded(char[] password)
        throws IOException, GeneralSecurityException
    {
        try
        {
            OutputEncryptor encOut = new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC).setProvider("BC").build(password);

            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            PKCS12PfxPduBuilder builder = new PKCS12PfxPduBuilder();

            for (String keyID : sharedPrivateKeyMap.getIDs())
            {
                SubjectPublicKeyInfo pubKey = this.fetchPublicKey(keyID);

                // TODO: perhaps add CA cert and trust anchor to key store if available
                PKCS12SafeBagBuilder eeCertBagBuilder = new PKCS12SafeBagBuilder(createCertificate(
                                                                 keyID, sharedPrivateKeyMap.getShare(keyID).getSequenceNo(), (PrivateKey)nodeContext.getNodeCAStore().getKey("nodeCA", new char[0])));

                eeCertBagBuilder.addBagAttribute(PKCS12SafeBag.friendlyNameAttribute, new DERBMPString(keyID));

                SubjectKeyIdentifier pubKeyId = extUtils.createSubjectKeyIdentifier(pubKey);

                eeCertBagBuilder.addBagAttribute(PKCS12SafeBag.localKeyIdAttribute, pubKeyId);

                PKCS12SafeBagBuilder keyBagBuilder = new PKCS12SafeBagBuilder(PrivateKeyInfoFactory.createPrivateKeyInfo(sharedPrivateKeyMap.getShare(keyID).getValue(), paramsMap.get(keyID)), encOut);

                keyBagBuilder.addBagAttribute(PKCS12SafeBag.friendlyNameAttribute, new DERBMPString(keyID));
                keyBagBuilder.addBagAttribute(PKCS12SafeBag.localKeyIdAttribute, pubKeyId);

                builder.addEncryptedData(new JcePKCSPBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC).setProvider("BC").build(password), new PKCS12SafeBag[] { eeCertBagBuilder.build() });

                builder.addData(keyBagBuilder.build());
            }

            PKCS12PfxPdu pfx = builder.build(new JcePKCS12MacCalculatorBuilder(NISTObjectIdentifiers.id_sha256), password);

            return pfx.getEncoded(ASN1Encoding.DL);
        }
        catch (PKCSException e)
        {
            throw new GeneralSecurityException("Unable to create key store: " + e.getMessage(), e);
        }
        catch (OperatorCreationException e)
        {
            throw new GeneralSecurityException("Unable to create operator: " + e.getMessage(), e);
        }
    }

    public synchronized void load(char[] password, byte[] encoding)
        throws IOException, GeneralSecurityException
    {
        try
        {
            PKCS12PfxPdu pfx = new PKCS12PfxPdu(encoding);
            InputDecryptorProvider inputDecryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder()
                .setProvider("BC").build(password);
            ContentInfo[] infos = pfx.getContentInfos();

            for (int i = 0; i != infos.length; i++)
            {
                if (infos[i].getContentType().equals(PKCSObjectIdentifiers.encryptedData))
                {
                    PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i], inputDecryptorProvider);

                    PKCS12SafeBag[] bags = dataFact.getSafeBags();

                    Attribute[] attributes = bags[0].getAttributes();

                    X509CertificateHolder cert = (X509CertificateHolder)bags[0].getBagValue();

                    String keyID = getKeyID(attributes);
                    BLS01PublicKeyParameters publicKeyParameters = BLSPublicKeyFactory.createKey(cert.getSubjectPublicKeyInfo());

                    paramsMap.put(keyID, publicKeyParameters.getParameters());
                    sharedPublicKeyMap.init(keyID, 1);
                    sharedPublicKeyMap.addValue(keyID, new ElementShare(
                        ASN1Integer.getInstance(cert.getExtension(XimixObjectIdentifiers.ximixShareIdExtension).getParsedValue()).getValue().intValue(),
                        publicKeyParameters.getPk()));

                    if (KeyUsage.fromExtensions(cert.getExtensions()).hasUsages(KeyUsage.digitalSignature))
                    {
                        signingKeys.add(keyID);
                    }
                }
                else
                {
                    PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i]);

                    PKCS12SafeBag[] bags = dataFact.getSafeBags();
                    String keyID = getKeyID(bags[0].getAttributes());

                    PKCS8EncryptedPrivateKeyInfo encInfo = (PKCS8EncryptedPrivateKeyInfo)bags[0].getBagValue();
                    PrivateKeyInfo info = encInfo.decryptPrivateKeyInfo(inputDecryptorProvider);

                    sharedPrivateKeyMap.init(keyID, 1);
                    sharedPrivateKeyMap.addValue(keyID, new BigIntegerShare(sharedPublicKeyMap.getShare(keyID).getSequenceNo(), ASN1Integer.getInstance(info.parsePrivateKey()).getValue()));
                }
            }
        }
        catch (PKCSException e)
        {
            throw new GeneralSecurityException("Unable to load key store: " + e.getMessage(), e);
        }
    }

    @Override
    public void addListener(KeyManagerListener listener)
    {
        listenerHandler.addListener(listener);
    }

    @Override
    public PrivateKeyOperator getPrivateKeyOperator(String keyID)
    {
        Share<BigInteger> privateKeyShare = sharedPrivateKeyMap.getShare(keyID);
        if (privateKeyShare == null)
        {
            return null;
        }

        return new JpbcPrivateKeyOperator(privateKeyShare.getSequenceNo(), paramsMap.get(keyID), privateKeyShare.getValue());
    }

    private X509CertificateHolder createCertificate(
        String keyID,
        int sequenceNo,
        PrivateKey privKey)
        throws GeneralSecurityException, OperatorCreationException, IOException
    {
        String name = "C=AU, O=Ximix Network Node, OU=" + nodeContext.getName();

        //
        // create the certificate - version 3
        //
        X509v3CertificateBuilder v3CertBuilder = new X509v3CertificateBuilder(
            new X500Name(name),
            BigInteger.valueOf(1),
            new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365)),
            new X500Name(name),
            this.fetchPublicKey(keyID));

        // we use keyUsage extension to distinguish between signing and encryption keys

        if (signingKeys.contains(keyID))
        {
            v3CertBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        }
        else
        {
            v3CertBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.dataEncipherment));
        }

        v3CertBuilder.addExtension(XimixObjectIdentifiers.ximixShareIdExtension, true, new ASN1Integer(sequenceNo));

        return v3CertBuilder.build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(privKey));
    }

    private String getKeyID(Attribute[] attributes)
    {
        for (Attribute attr : attributes)
        {
            if (PKCS12SafeBag.friendlyNameAttribute.equals(attr.getAttrType()))
            {
                return DERBMPString.getInstance(attr.getAttrValues().getObjectAt(0)).getString();
            }
        }

        throw new IllegalStateException("No friendlyNameAttribute found.");
    }

    private long makeSeed(byte[] bytes)
    {
        long rv = 0;

        for (int i = 0; i != bytes.length; i++)
        {
            rv += 37 * rv + bytes[i];
        }

        return rv;
    }
}
