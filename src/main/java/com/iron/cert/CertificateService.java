package com.iron.cert;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

import org.apache.tomcat.util.http.fileupload.ByteArrayOutputStream;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

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

    public String generatePKCS7(X509Certificate certificate, KeyPair keyPair) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(
            new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signer, certificate));
        generator.addCertificate(new X509CertificateHolder(certificate.getEncoded()));
    
        CMSSignedData signedData = generator.generate(new CMSProcessableByteArray(new byte[0]), true);
        return encodeToPEM(signedData.getEncoded(), "PKCS7");
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

    private String encodeToPEM(byte[] data, String type) {
        String base64Encoded = Base64.getEncoder().encodeToString(data);
        return "-----BEGIN " + type + "-----\n" +
               base64Encoded.replaceAll("(.{64})", "$1\n") + // Split into lines of 64 characters
               "\n-----END " + type + "-----\n";
    }

    public byte[] convertToPKCS12(X509Certificate certificate, KeyPair keyPair, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
    
        // KeyStore.PrivateKeyEntry 생성자에 PrivateKey 객체와 Certificate 배열을 전달합니다.
        KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(
            keyPair.getPrivate(), // PrivateKey 추출
            new java.security.cert.Certificate[]{certificate} // Certificate 배열
        );
    
        keyStore.setEntry("private", privateKeyEntry, new KeyStore.PasswordProtection(password.toCharArray()));
    
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        keyStore.store(baos, password.toCharArray());
        return baos.toByteArray();
    }

}