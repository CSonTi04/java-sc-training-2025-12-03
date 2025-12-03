package jca;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CipherMain {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        for (int i = 0; i < 10; i++) {
            var encrypted = cipherHelloWorld();
            var decrypted = decipherHelloWorld(encrypted);
            System.out.println("Decrypted: " + decrypted);
            System.out.println();
        }
    }

    private static String cipherHelloWorld() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        var input = "Hello World!".getBytes(StandardCharsets.UTF_8);//azért, hogy oprendszerfüggetlen legyen a kódolás
        //kulcs generálás
        var keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256); // 128, 192, or 256 bits - alapból erős random, de aparméterezhető is
        var key = keyGenerator.generateKey();
        //IV - initialization vector generálás - AES CBC módhoz kell
        byte [] iv = new byte[12]; // AES block size is 12 bytes, IV-nek mindig random és egyedinek kell lennie
        var random = java.security.SecureRandom.getInstanceStrong();//oprendszertől független erős random
        random.nextBytes(iv);
        //titkosítás
        var cipher = Cipher.getInstance("AES/GCM/NoPadding");
        var spec = new GCMParameterSpec(128, iv);//hitelességet ellenőrző tag hossza 128 bit

        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        var encrypted = cipher.doFinal(input);

        // Concatenate IV and encrypted data with a dot delimiter for decryption
        var hexFormat = HexFormat.of();
        var result = hexFormat.formatHex(iv) + "." + hexFormat.formatHex(encrypted) + "." + hexFormat.formatHex(key.getEncoded());
        System.out.println("IV.Encrypted.Key: " + result);
        return result;
    }

    private static String decipherHelloWorld(String encryptedData) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        var hexFormat = HexFormat.of();

        // Split the encrypted data into IV, encrypted bytes, and key
        var parts = encryptedData.split("\\.");
        var iv = hexFormat.parseHex(parts[0]);
        var encrypted = hexFormat.parseHex(parts[1]);
        var keyBytes = hexFormat.parseHex(parts[2]);

        // Reconstruct the key
        var key = new SecretKeySpec(keyBytes, "AES");

        // Decipher
        var cipher = Cipher.getInstance("AES/GCM/NoPadding");
        var spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        var decrypted = cipher.doFinal(encrypted);

        return new String(decrypted, StandardCharsets.UTF_8);
    }
}
