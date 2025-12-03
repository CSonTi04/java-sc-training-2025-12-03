package jca;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public class HashMain {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        var input = "Hello, World!".getBytes();//itt lehetne vájlt is beolvasni természetesen
        var digest = MessageDigest.getInstance("SHA-256");//Ide provider-t is meg lehetne adni, pl bouncy castle
        var hash = digest.digest(input);
        var hex = HexFormat.of();
        var formattedHex = hex.formatHex(hash);
        System.out.println("Input: " + new String(input));
        System.out.println("SHA-256 Hash: " + formattedHex);
    }
}
