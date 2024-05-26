package com.iron.cert;


import java.io.StringReader;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

public class CertificateUtils {

    public static PrivateKey readPrivateKeyFromPEM(String pem) throws Exception {
        try (PEMParser pemParser = new PEMParser(new StringReader(pem))) {
            PEMKeyPair keyPair = (PEMKeyPair) pemParser.readObject();
            return new JcaPEMKeyConverter().getPrivateKey(keyPair.getPrivateKeyInfo());
        }
    }

    public static PublicKey readPublicKeyFromPEM(String pem) throws Exception {
        try (PEMParser pemParser = new PEMParser(new StringReader(pem))) {
            X509Certificate certificate = (X509Certificate) pemParser.readObject();
            return certificate.getPublicKey();
        }
    }

    public static X509Certificate readCertificateFromPEM(String pem) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        StringReader reader = new StringReader(pem);
        try (PEMParser pemParser = new PEMParser(reader)) {
            Object object = pemParser.readObject();
            if (object instanceof X509CertificateHolder) {
                return new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) object);
            } else if (object instanceof Certificate) {
                byte[] encoded = ((Certificate) object).getEncoded();
                return (X509Certificate) factory.generateCertificate(new java.io.ByteArrayInputStream(encoded));
            }
            throw new IllegalArgumentException("Provided PEM data does not contain a valid X.509 certificate");
        }
    }   
}