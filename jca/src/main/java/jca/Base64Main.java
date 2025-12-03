package jca;

import java.util.Base64;

public class Base64Main {
    public static  void main(String[] args) {
        String original = "Hello, World!";
        String encoded = Base64.getEncoder().encodeToString(original.getBytes());
        byte[] decodedBytes = Base64.getDecoder().decode(encoded);
        String decoded = new String(decodedBytes);

        System.out.println("Original: " + original);
        System.out.println("Encoded: " + encoded);
        System.out.println("Decoded: " + decoded);
    }
}
