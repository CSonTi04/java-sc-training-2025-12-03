package jca;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

public class MacMain {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
        var input = "Hello World!".getBytes(StandardCharsets.UTF_8);//azért, hogy oprendszerfüggetlen legyen a kódolás
        //kulcs generálás
        var keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256); // 128, 192, or 256 bits - alapból erős random, de aparméterezhető is
        var key = keyGenerator.generateKey();

        var macGenerator = Mac.getInstance("HmacSHA256");
        macGenerator.init(key);

        var signature = macGenerator.doFinal(input);
        System.out.println("Signature: " + HexFormat.of().formatHex(signature));

        //ellenőrzés - BOB
        var macVerifier = Mac.getInstance("HmacSHA256");
        macVerifier.init(key);
        var verifySignature = macVerifier.doFinal(input);
        System.out.println("VerifySignature: " + HexFormat.of().formatHex(verifySignature));
        var isValid = Arrays.equals(signature, verifySignature);
        System.out.println("Is valid: " + isValid);
    }
}
