package jca;

import java.util.HexFormat;

public class HexMain {
    public static void main(String[] args) {
        var input = "Hello, World!";
        var hexEncoded = HexFormat.of();
        var formattedHex = hexEncoded.formatHex(input.getBytes());
        System.out.println(formattedHex);
    }
}
