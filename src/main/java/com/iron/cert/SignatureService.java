package com.iron.cert;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import com.google.gson.Gson;

public class SignatureService {

    public String signMessage(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    public boolean verifyMessage(String message, String signatureStr, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        byte[] signatureBytes = Base64.getDecoder().decode(signatureStr);
        return signature.verify(signatureBytes);
    }


    public Map<String, Object> verifyPKCS7(String pkcs7Data) throws Exception {
        byte[] pkcs7Bytes = Base64.getDecoder().decode(pkcs7Data);
        CMSSignedData signedData = new CMSSignedData(pkcs7Bytes);

        Store certs = signedData.getCertificates();
        SignerInformation signer = (SignerInformation) signedData.getSignerInfos().getSigners().iterator().next();
        
        boolean isValid = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build((X509CertificateHolder) certs.getMatches(signer.getSID()).iterator().next()));
        String originalMessage = new String((byte[]) signedData.getSignedContent().getContent());
        System.out.println("originalMessage : "+originalMessage);
        
        
        Map<String, Object> result = new HashMap<>();
        result.put("isValid", isValid);
        result.put("originalMessage", originalMessage);

        return result;
    }

    public String generateSignedPKCS7(String message, PrivateKey privateKey, X509Certificate certificate) throws Exception {
        // 서명 데이터 생성기 초기화
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);

        // 서명 정보 생성기 추가
        generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signer, new JcaX509CertificateHolder(certificate)));

        // 인증서 추가
        List<X509Certificate> certList = new ArrayList<>();
        certList.add(certificate);
        generator.addCertificates(new JcaCertStore(certList));

        // 메시지를 CMS 데이터로 변환
        CMSProcessableByteArray msg = new CMSProcessableByteArray(message.getBytes());

        // 서명된 데이터 생성
        CMSSignedData signedData = generator.generate(msg, true);

        // PEM 형식으로 인코딩
        return encodeToPEM(signedData.getEncoded(), "PKCS7");
    }

    private String encodeToPEM(byte[] data, String type) {
        String base64Encoded = Base64.getEncoder().encodeToString(data);
        return "-----BEGIN " + type + "-----\n" +
               base64Encoded.replaceAll("(.{64})", "$1\n") + // Split into lines of 64 characters
               "\n-----END " + type + "-----\n";
    }

    public String generatePKCS7PEM(String pkcs7Data) {
        String pemData = "-----BEGIN PKCS7-----\n";
        pemData += Base64.getEncoder().encodeToString(pkcs7Data.getBytes());
        pemData += "\n-----END PKCS7-----";
        return pemData;
    }

    
    public String loadPrivateKeyAndSignData(String base64EncodedPkcs12, String storePassword, Map<String, String> dataToSign) throws Exception {

        byte[] pkcs12Data = Base64.getDecoder().decode(base64EncodedPkcs12);

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new ByteArrayInputStream(pkcs12Data), storePassword.toCharArray());

        String alias = keyStore.aliases().nextElement();  // Assuming there is only one key
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, storePassword.toCharArray());
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);

        String jsonData = new Gson().toJson(dataToSign);

        return generateSignedPKCS7(jsonData, privateKey, certificate);
    }
}