package isp.secrecy;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * I0->I1->A1->B1->A2->B2->A3->B3->A4->B4->[A5]
 * <p/>
 * EXERCISE A5:
 * <p/>
 * EXERCISE:
 * - Study the example.
 * - What happens if ECB modes is preferred over CBC (or other modes) operation
 * of cipher algorithm? (see http://en.wikipedia.org/wiki/Initialization_vector)
 * - Which security properties have to preserved when sending Algorithm Parameters
 * such as Initialization Vector?
 * <p/>
 * - Homework: Oscar intercepts the message and would like to decrypt the ciphertext. Help Oscar to
 * decrypt the ciphertext using brute force key search (exhaustive key search) if Oscar knows
 * that Alice has send the following message "I would like to keep this text confidential Bob. Kind regards, Alice."
 * (Known-plaintext attack)
 * <p/>
 * INFO:
 * http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#Cipher
 *
 * @author Iztok Starc <iztok.starc@fri.uni-lj.si>
 * @version 1
 * @date 19. 12. 2011
 */
public class SymmetricCipherExample {
    // BLOCK CIPHERS
    public static final String[] ALG1 = { "DES", "DES/ECB/PKCS5Padding" };
    public static final String[] ALG2 = { "DESede", "DESede/ECB/PKCS5Padding" };
    public static final String[] ALG3 = { "AES", "AES/ECB/PKCS5Padding" };
    public static final String[] ALG4 = { "AES", "AES/CBC/PKCS5Padding" };

    // STREAM CIPHER
    public static final String[] ALG5 = { "RC4", "RC4" };

    public static void main(String[] args)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException, IOException {

        /**
         * STEP 1.
         * Alice and Bob agree upon a cipher algorithm and a shared secret session key 
         * is created that will be used for encryption and decryption.
         */
        final Key key = KeyGenerator.getInstance(ALG4[0]).generateKey();

        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        System.out.println("[MESSAGE] " + message);

        final byte[] clearText = message.getBytes("UTF-8");
        System.out.println("[CLEAR_TEXT] " + DatatypeConverter.printHexBinary(clearText));

        /**
         * STEP 2.
         * Alice creates Cipher object defining cipher algorithm.
         * Alice encrypts clear-text and sends to Bob.
         *
         * In addition, Alice sends to Bob necessary algorithm parameters 
         * such as Initialization vector, if necessary.
         */
        final Cipher cipher = Cipher.getInstance(ALG4[1]);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        final AlgorithmParameters ap = cipher.getParameters();
        final byte[] cipherText = cipher.doFinal(clearText);

        //STEP 3: Print out cipher text (hex). This is what an attacker would see
        System.out.println("[CIPHER_TEXT] " + DatatypeConverter.printHexBinary(cipherText));

        /**
         * STEP 4.
         * Bob creates Cipher object, defining cipher algorithm, secret key and
         * algorithm initialization parameters such as Initialization vector (IV),
         * if necessary.
         *
         * Bob decrypts cipher text
         *
         */

        // What happens if an attacker changes a value in the cipher text?
        // Set the cipher to ALG5[0]
        // cipherText[10] = (byte) 150;

        final Cipher cipher2 = Cipher.getInstance(ALG4[1]);
        cipher2.init(Cipher.DECRYPT_MODE, key, ap);
        // what happens if our key is incorrect? (make sure to set ALG5[0] to all algorithm selections
        //cipher2.init(Cipher.DECRYPT_MODE, KeyGenerator.getInstance(ALG5[0]).generateKey(), ap);
        final byte[] decryptedText = cipher2.doFinal(cipherText);
        System.out.println("[DECRYPTED_TEXT] " + DatatypeConverter.printHexBinary(decryptedText));

        /**
         * STEP 5.
         * Bob prints out clear-text.
         */
        System.out.println("[MESSAGE] " + new String(decryptedText, "UTF-8"));

    }
}
