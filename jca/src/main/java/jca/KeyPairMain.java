package jca;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;

public class KeyPairMain {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);//n bit, a modulos mérete
        var keyPair = keyPairGenerator.generateKeyPair();
        //private key
        var privateKey = keyPair.getPrivate();
        System.out.println("Private Key: " + privateKey);
        System.out.println("Private Key algorithm: " + privateKey.getAlgorithm());
        System.out.println("Private Key format: " + privateKey.getFormat());
        System.out.println("Private Key: " + Arrays.toString(privateKey.getEncoded()));

        var rsaPrivateKey = (RSAPrivateKey) privateKey;
        System.out.println("Modulus: " + rsaPrivateKey.getModulus());
        System.out.println("Private Exponent: " + rsaPrivateKey.getPrivateExponent());

        //public key

        var publicKey = keyPair.getPublic();
        System.out.println("Public Key: " + publicKey);
        System.out.println("Public Key algorithm: " + publicKey.getAlgorithm());
        System.out.println("Public Key format: " + publicKey.getFormat());
    }
}
