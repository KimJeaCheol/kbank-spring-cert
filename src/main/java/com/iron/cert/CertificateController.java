package com.iron.cert;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;

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

    @GetMapping("/generate")
    public String generateCertificate() throws Exception {
        KeyPair keyPair = certificateService.generateKeyPair();
        X509Certificate certificate = certificateService.generateCertificate(keyPair);
        String certPem = certificateService.writeCertificateToPEM(certificate);
        String keyPem = certificateService.writePrivateKeyToPEM(keyPair);

        return "Certificate:\n" + certPem + "\nPrivate Key:\n" + keyPem;
    }

    @PostMapping("/sign")
    public String signMessage(@RequestParam String message, @RequestParam String privateKeyPem) throws Exception {
        PrivateKey privateKey = CertificateUtils.readPrivateKeyFromPEM(privateKeyPem);
        return signatureService.signMessage(message, privateKey);
    }

    @PostMapping("/verify")
    public boolean verifyMessage(@RequestParam String message, @RequestParam String signature, @RequestParam String certificatePem) throws Exception {
        PublicKey publicKey = CertificateUtils.readPublicKeyFromPEM(certificatePem);
        return signatureService.verifyMessage(message, signature, publicKey);
    }

    @PostMapping("/getPublicKey")
    public String getPublicKeyFromCert(String pemCert) throws Exception {
        PublicKey publicKey = certificateService.getPublicKeyFromCert(pemCert);
        return "Public Key:\n" + Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }
}