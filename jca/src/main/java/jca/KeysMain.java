package jca;

import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import javax.crypto.KeyGenerator;

public class KeysMain {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        var keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256); // 128, 192, or 256 bits - alapból erős random, de aparméterezhető is
        var secretKey = keyGenerator.generateKey();
        var hexEncoded = HexFormat.of();
        var formattedHex = hexEncoded.formatHex(secretKey.getEncoded());
        //itt jön a bitkolbász :D
        System.out.println("Generated AES Key (Hex): " + formattedHex);
    }
}
