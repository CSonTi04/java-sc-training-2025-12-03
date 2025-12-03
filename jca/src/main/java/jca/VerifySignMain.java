package jca;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class VerifySignMain {
    public static void main(String[] args) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, SignatureException, InvalidKeyException {
        var data = "Hello world".getBytes(StandardCharsets.UTF_8);

        var keyStore = KeyStore.getInstance("PKCS12");

        // Use absolute path or search in parent directory of project
        var keystorePath = Path.of("C:/Repos/java-sc-training-2025-12-03/training-keystore.p12");
        if (!Files.exists(keystorePath)) {
            // Fallback to relative path
            keystorePath = Path.of("../training-keystore.p12");
        }

        try (var input = Files.newInputStream(keystorePath)) {
            keyStore.load(input, "changeit".toCharArray());
        }

        var certificate = (X509Certificate) keyStore.getCertificate("training-key");

        var signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(certificate.getPublicKey());

        signature.update(data);

        var signatureBytes = Files.readAllBytes(Path.of("signature.bin"));
        var valid = signature.verify(signatureBytes);

        System.out.println("Valid: " + valid);

    }
}
