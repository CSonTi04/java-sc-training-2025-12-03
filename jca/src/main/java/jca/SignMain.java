package jca;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.HexFormat;

public class SignMain {
    public static void main(String[] args) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, SignatureException {
        var data = "Hello world".getBytes(StandardCharsets.UTF_8);

        var keyStorePath = KeyStore.getInstance("PKCS12");

        // Use absolute path or search in parent directory of project
        var keystorePath = Path.of("C:/Repos/java-sc-training-2025-12-03/training-keystore.p12");
        if (!Files.exists(keystorePath)) {
            // Fallback to relative path
            keystorePath = Path.of("../training-keystore.p12");
        }

        try (var input = Files.newInputStream(keystorePath)) {
            keyStorePath.load(input, "changeit".toCharArray());
        }

        var privateKey = (PrivateKey) keyStorePath.getKey("training-key", "changeit".toCharArray());

        var signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        var signBytes = signature.sign();

        var hex = HexFormat.of();
        System.out.println(hex.formatHex(signBytes));
    }
}
