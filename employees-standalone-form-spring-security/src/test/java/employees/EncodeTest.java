package employees;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

public class EncodeTest {

    @Test
    public void encodePassword() {
        Argon2PasswordEncoder encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
        for (int i = 0; i < 10; i++) {
            String encoded = encoder.encode("password");
            System.out.println(encoded);
        }
    }

    @Test
    public void encodeDegPassword() {
        Argon2PasswordEncoder encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
        System.out.println(encoder.encode("user"));
        System.out.println(encoder.encode("admin"));
    }
}
