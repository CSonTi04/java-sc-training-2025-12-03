package jca;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class RandomMain {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        //var random = new Random();//Crypt célre nem használható, ott SecureRandom kell minimum
        //var random = new SecureRandom();
        //var random = SecureRandom.getInstance("Windows-PRNG");//Lehet algoritmust is megadni
        //kevesebb entrópia, de mondjuk a getInstanceStrong az blokkolja a szálakat
        //elkerlő megoldás a példány chache-elése, mondjuk thread local változóban
        var random = SecureRandom.getInstanceStrong();//Erősebb algoritmusú SecureRandom példány
        byte[] randomBytes = new byte[16]; // 16 bytes = 128 bits
        random.nextBytes(randomBytes);
        System.out.println(Arrays.toString(randomBytes));
    }
}
