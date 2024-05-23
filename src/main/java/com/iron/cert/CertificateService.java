package com.iron.cert;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CertificateService {

    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    public X509Certificate generateCertificate(KeyPair keyPair) throws Exception {
        X500Name issuer = new X500Name("CN=RootCA");
        X500Name subject = new X500Name("CN=User");

        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        Date notAfter = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000);

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, keyPair.getPublic());

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        X509CertificateHolder certHolder = certBuilder.build(signerBuilder.build(keyPair.getPrivate()));

        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    public String writeCertificateToPEM(X509Certificate certificate) throws Exception {
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(certificate);
        }
        return writer.toString();
    }

    public String writePrivateKeyToPEM(KeyPair keyPair) throws Exception {
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(keyPair.getPrivate());
        }
        return writer.toString();
    }
        public PublicKey getPublicKeyFromCert(String pemCert) throws Exception {
        String pem = pemCert.replace("-----BEGIN CERTIFICATE-----", "")
                            .replace("-----END CERTIFICATE-----", "")
                            .replaceAll("\\s", "");

        byte[] encoded = Base64.getDecoder().decode(pem);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(encoded));
        return certificate.getPublicKey();
    }
}