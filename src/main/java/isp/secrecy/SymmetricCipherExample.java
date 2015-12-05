package isp.secrecy; /**
 * I0->I1->A1->B1->A2->B2->A3->B3->A4->B4->[A5]
 * <p/>
 * EXERCISE A5:
 * <p/>
 * EXERCISE:
 * - Study this example.
 * - What happens if ECB modes is preferred over CBC (or other modes) operation
 * of cipher algorithm? (see http://en.wikipedia.org/wiki/Initialization_vector)
 * - Which security properties have to preserved when sending Algorithm Parameters
 * such as Initialization Vector?
 * <p/>
 * - Oscar intercepts the message and would like to decrypt the ciphertext. Help Oscar to
 * decrypt the ciphertext using brute force key search (exhaustive key search) if Oscar knows
 * that Alice has send the following message "I would like to keep this text confidential Bob. Kind regards, Alice."
 * (Known-plaintext attack)
 * <p/>
 * INFO:
 * http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#Cipher
 *
 * @author Iztok Starc <iztok.starc@fri.uni-lj.si>
 * @date 19. 12. 2011
 * @version 1
 */

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;

/**
 *
 * @author iztok
 */
public class SymmetricCipherExample {

    private static Key symKey;
    private static AlgorithmParameters ap;

    /**
     * BLOCK CIPHER
     */
    public static String[] ALG1 = { "DES", "DES/ECB/PKCS5Padding" };
    public static String[] ALG2 = { "DESede", "DESede/ECB/PKCS5Padding" };
    public static String[] ALG3 = { "AES", "AES/ECB/PKCS5Padding" };
    public static String[] ALG4 = { "AES", "AES/CBC/PKCS5Padding" };

    /**
     * STREAM CIPHER
     */
    public static String[] ALG5 = { "RC4", "RC4" };

    /**
     * TEXT TO ENCRYPT/DECRYPT
     */
    public static String TEXT = "I would like to keep this text confidential Bob. Kind regards, Alice.";

    public static void main(String[] args)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException, IOException {

        /**
         * STEP 1.
         * Alice and Bob agree upon a cipher algorithm and a shared secret session key 
         * is created that will be used for encryption and decryption.
         */
        symKey = KeyGenerator.getInstance(ALG5[0]).generateKey();

        /**
         * STEP 2.
         * Alice creates Cipher object defining cipher algorithm.
         * Alice encrypts clear-text and sends to Bob.
         *
         * In addition, Alice sends to Bob necessary algorithm parameters 
         * such as Initialization vector, if necessary.
         */
        Cipher c1 = Cipher.getInstance(ALG5[1]);
        c1.init(Cipher.ENCRYPT_MODE, symKey);
        ap = c1.getParameters();
        byte[] cipher_TEXT = c1.doFinal(TEXT.getBytes());

        /**
         * STEP 3.
         * Print out ciphertext (hex). Attacker would see this text.
         */
        Formatter frm1 = new Formatter();
        for (byte b : cipher_TEXT)
            frm1.format("%02x", b);
        System.out.println("[CIPHERTEXT] " + frm1.toString());

        /**
         * STEP 4.
         * Bob creates Cipher object, defining cipher algorithm, secret key and
         * algorithm initialization parameters such as Initialization vector (IV),
         * if necessary.
         *
         * Bob decrypts ciphertext
         *
         */
        Cipher c2 = Cipher.getInstance(ALG5[1]);
        c2.init(Cipher.DECRYPT_MODE, symKey, ap);
        //c2.init(Cipher.DECRYPT_MODE, KeyGenerator.getInstance(ALG5[0]).generateKey(), ap); // Kaj se zgodi, ko nimamo pravega ključa?
        byte[] clear_TEXT = c2.doFinal(cipher_TEXT);

        /**
         * STEP 5.
         * Bob prints out clear-text.
         */
        System.out.println("[CLEARTEXT] " + new String(clear_TEXT));

    }
}
