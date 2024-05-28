package com.iron.cert;

import java.net.URLDecoder;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/cert")
public class CertificateController {

    private final CertificateService certificateService = new CertificateService();
    private final SignatureService signatureService = new SignatureService();

    // @GetMapping("/generate")
    // public String  generateCertificate(@RequestParam String keyPassword) throws Exception {
    //     KeyPair keyPair = certificateService.generateKeyPair();
    //     X509Certificate certificate = certificateService.generateCertificate(keyPair);
    
    //     // 인증서와 개인키를 PEM 형식으로 변환
    //     String certPem = certificateService.writeCertificateToPEM(certificate);
    //     String keyPem = certificateService.writePrivateKeyToPEM(keyPair);  // 이 예제에서는 사용하지 않지만 참고로 제공
    
    //     // 개인키를 PKCS#12 포맷으로 암호화하고 Base64 인코딩
    //     byte[] pfxData = certificateService.convertToPKCS12(certificate, keyPair, keyPassword);
    //     String base64EncodedPkcs12 = Base64.getEncoder().encodeToString(pfxData);
    
    //     return "Certificate:\n" + certPem + "\nPrivate Key PKCS#12:\n" + base64EncodedPkcs12;
    // }

    @GetMapping("/generate")
    public String generateCertificate(@RequestParam String keyPassword) throws Exception {
        KeyPair keyPair = certificateService.generateKeyPair();
        X509Certificate certificate = certificateService.generateCertificate(keyPair);
        
        // Convert the certificate and private key to PKCS#12 format and Base64 encode
        byte[] pfxData = certificateService.convertToPKCS12(certificate, keyPair, keyPassword);
        String base64EncodedPkcs12 = Base64.getEncoder().encodeToString(pfxData);
        
        return "Certificate (PEM):\n" + certificateService.writeCertificateToPEM(certificate) +
            "\nPrivate Key (PKCS#12):\n" + base64EncodedPkcs12;
    }
    
    @GetMapping("/generate-pkcs7")
    public String generatePKCS7() throws Exception {
        KeyPair keyPair = certificateService.generateKeyPair();
        X509Certificate certificate = certificateService.generateCertificate(keyPair);
        return certificateService.generatePKCS7(certificate, keyPair);
    }

    // @PostMapping("/sign")
    // public String signMessage(@RequestParam String message, @RequestParam String privateKeyPem, @RequestParam String certPem) throws Exception {
    //     PrivateKey privateKey = CertificateUtils.readPrivateKeyFromPEM(privateKeyPem);
    //     X509Certificate certificate = CertificateUtils.readCertificateFromPEM(certPem);

    //     Map<String, String> data = new HashMap<>();
    //     data.put("message", message);
    //     data.put("timestamp", String.valueOf(System.currentTimeMillis()));  // 예시 추가 데이터
    //     String jsonData = new Gson().toJson(data);
    
    //     return signatureService.generateSignedPKCS7(jsonData, privateKey, certificate);
    // }
    @PostMapping("/sign")
    public String signMessage(@RequestParam String message,
                              @RequestParam String base64EncodedPkcs12,
                              @RequestParam String keyPassword) throws Exception {

        Map<String, String> dataToSign = new HashMap<>();
        dataToSign.put("message", message);
        dataToSign.put("timestamp", String.valueOf(System.currentTimeMillis()));

        return signatureService.loadPrivateKeyAndSignData(base64EncodedPkcs12, keyPassword, dataToSign);
    }

    @PostMapping("/verify")
    public boolean verifyMessage(@RequestParam String message, @RequestParam String signature, @RequestParam String certificatePem) throws Exception {
        PublicKey publicKey = CertificateUtils.readPublicKeyFromPEM(certificatePem);
        return signatureService.verifyMessage(message, signature, publicKey);
    }

    @PostMapping("/verify-pkcs7")
    public ResponseEntity<?> verifyPKCS7(@RequestParam String pkcs7Data) {
        String cleanedBase64 = cleanBase64String(pkcs7Data);

        if (!isValidBase64(cleanedBase64)) {
            return ResponseEntity.badRequest().body("Invalid Base64 data provided.");
        }
        try {
            Map<String, Object> result = signatureService.verifyPKCS7(cleanedBase64);
            boolean isValid = (boolean) result.get("isValid");
            String originalMessage = (String) result.get("originalMessage");

            Map<String, Object> response = new HashMap<>();
            response.put("isValid", isValid);
            response.put("originalMessage", URLDecoder.decode(URLDecoder.decode(originalMessage, "UTF-8"),"UTF-8"));

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Error verifying PKCS7 data: " + e.getMessage());
        }
    }

    @PostMapping("/getPublicKey")
    public String getPublicKeyFromCert(String pemCert) throws Exception {
        PublicKey publicKey = certificateService.getPublicKeyFromCert(pemCert);
        return "Public Key:\n" + Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public static boolean isValidBase64(String base64) {
        try {
            System.out.println(base64);
            Base64.getDecoder().decode(base64);
            return true;
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static String cleanBase64String(String pkcs7Data) {
        // 제거: 공백, 개행, 리턴, 탭
        String base64Data = pkcs7Data.replace("-----BEGIN PKCS7-----", "")
        .replace("-----END PKCS7-----", "")
        .replaceAll("\\s", ""); // 모든 공백과 줄바꿈 제거
        return base64Data;
    }
}