package jca;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;

public class CertificateMain {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, CertificateException, IOException, KeyStoreException {
        //bouncy castle-t fel kell venni mint provider
        Security.addProvider(new BouncyCastleProvider());

        var generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(2048);
        var keyPair = generator.generateKeyPair();

        //leíró információk létrehozása - X,500-as szabvány szerint
        var distinguishedName = new X500Name("CN=TrainingSelfSignedCertificate, O=MyOrganization, C=HU");
        var sysDate = System.currentTimeMillis();
        var serialNumber = java.math.BigInteger.valueOf(sysDate);
        var start = new java.util.Date(sysDate);
        var end = new java.util.Date(sysDate + Duration.ofDays(365).toMillis()); //1 év múlva lejár

        //Tanúsítvány létrehozása
        var certificateBuilder = new JcaX509v3CertificateBuilder(
                distinguishedName,
                serialNumber,
                start,
                end,
                distinguishedName,
                keyPair.getPublic()
        );

        //aláírás
        var signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.getPrivate());

        var holder = certificateBuilder.build(signer).toASN1Structure();
        System.out.println(holder);

        //X509 tanúsítvány létrehozása - ez megint Java SE

        var cert = new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(certificateBuilder.build(signer));

        System.out.println("################################################################################");
        //olvasható, de nem szabványos formátum
        System.out.println(cert);
        //DER formátum - bináris - windows alatt .cer vagy .der kiterjesztés
        Files.write(Path.of("training-certificate.der"), cert.getEncoded());
        //PEM formátum - Base64 kódolt ASCII - .pem kiterjesztés
        //ez egy x509 tanusítvány base64-ezve
        try (var writer = Files.newBufferedWriter(Path.of("training-certificate.pem"))) {
            var pemWriter = new JcaPEMWriter(writer);
            pemWriter.writeObject(cert);
            pemWriter.close();
        }

        Files.write(Path.of("training-certificate-private.der"), keyPair.getPrivate().getEncoded());
        //Privát kulcs
        OutputEncryptor encryptor = new JceOpenSSLPKCS8EncryptorBuilder(
                PKCS8Generator.PBE_SHA1_3DES)
                .setRandom(new SecureRandom())
                .setPassword("changeit".toCharArray())
                .build();

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
        PrivateKeyInfo pki = PrivateKeyInfo.getInstance(spec.getEncoded());
        PKCS8Generator gen = new PKCS8Generator(pki, encryptor);

        try (var writer = Files.newBufferedWriter(Path.of("training-certificate-private.pem"))) {
            var pemWriter = new JcaPEMWriter(writer);
            pemWriter.writeObject(gen);
            pemWriter.close();
        }

        //Tanúsítvány és kulcs pár mentése PKCS#12 keystore formátumban
        var keyStore = KeyStore.getInstance("PKCS12", "BC");
        keyStore.load(null, null);
        keyStore.setKeyEntry("training-key", keyPair.getPrivate(), "changeit".toCharArray(),new X509Certificate[]{cert});
        try (var fos = Files.newOutputStream(Path.of("training-keystore.p12"))) {
            keyStore.store(fos, "changeit".toCharArray());
        }

        // Egy olyan kulcstár generálása amiben csak a tanúsítvány van benne
        keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null); // Ha ez nincs, akkor nem inicializált, és exception-t dob
        keyStore.setCertificateEntry("training-certificate", cert);

        try (var output = Files.newOutputStream(Path.of("training-keystore-just-certificate.p12"))) {
            keyStore.store(output, "secret".toCharArray());
        }
    }
}
