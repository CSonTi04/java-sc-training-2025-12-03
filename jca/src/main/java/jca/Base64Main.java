package jca;

import java.util.Base64;

public class Base64Main {
    public static  void main(String[] args) {
        String original = "Hello, World!"; String encoded = Base64.getEncoder().encodeToString(original.getBytes()); byte[] decodedBytes = Base64.getDecoder().decode(encoded); String decoded = new String(decodedBytes);
        System.out.println("Original: " + original);
        System.out.println("Encoded: " + encoded);
        System.out.println("Decoded: " + decoded);

        // Example with whitespace and control characters
        String withSpecialChars = "Text\nwith\ttabs\rand\nnewlines";
        String encodedSpecial = Base64.getEncoder().encodeToString(withSpecialChars.getBytes());
        byte[] decodedSpecialBytes = Base64.getDecoder().decode(encodedSpecial);
        String decodedSpecial = new String(decodedSpecialBytes);

        System.out.println("\nOriginal with special chars: " + withSpecialChars.replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r"));
        System.out.println("Encoded: " + encodedSpecial);
        System.out.println("Decoded: " + decodedSpecial.replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r"));
    }
}
