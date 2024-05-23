package com.iron.cert;


import java.io.StringReader;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

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
}