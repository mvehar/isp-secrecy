package isp.secrecy;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * I0->I1->A1->B1->A2->B2->A3->B3->[A4]
 * <p/>
 * EXERCISE A4:
 * <p/>
 * EXERCISE: Study the example.
 * <p/>
 * INFO:
 * http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#Cipher
 *
 * @author Iztok Starc <iztok.starc@fri.uni-lj.si>
 * @version 1
 * @date 19. 12. 2011
 */
public class AsymmetricCipherExample {

    public static void main(String[] args)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, UnsupportedEncodingException {

        final String algorithm = "RSA";
        final String text = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        final byte[] clearText = text.getBytes("UTF-8");

        System.out.println("Clear text:\n" + text);
        System.out.println("Clear text in HEX:\n" + DatatypeConverter.printHexBinary(clearText));

        // STEP 1: Bob creates his public and private key pair.
        // Alice receives Bob's public key.
        final KeyPair bobKP = KeyPairGenerator.getInstance(algorithm).generateKeyPair();

        // STEP 2: Alice creates Cipher object defining cipher algorithm.
        // She then encrypts the clear-text and sends it to Bob.
        final Cipher encryptionCipher = Cipher.getInstance(algorithm);
        encryptionCipher.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
        final byte[] cipherText = encryptionCipher.doFinal(clearText);

        // STEP 3: Display cipher text in hex. This is what an attacker would see,
        // if she intercepted the message.
        System.out.println("Cipher text in HEX:\n" + DatatypeConverter.printHexBinary(cipherText));

        // STEP 4: Bob decrypts the cipher text using the same algorithm and his private key.
        final Cipher decryptionCipher = Cipher.getInstance(algorithm);
        decryptionCipher.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
        final byte[] decryptedText = decryptionCipher.doFinal(cipherText);

        // STEP 5: Bob displays the clear text
        System.out.println("Decrypted text in HEX:\n" + DatatypeConverter.printHexBinary(decryptedText));
        final String decryptedTextAsString = new String(decryptedText, "UTF-8");
        System.out.println("Decrypted text:\n" + decryptedTextAsString);
    }
}
