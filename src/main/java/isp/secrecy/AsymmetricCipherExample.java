package isp.secrecy; /**
 * I0->I1->A1->B1->A2->B2->A3->B3->[A4]
 * 
 * EXERCISE A4:
 * 
 * EXERCISE:
 * - Study this example.
 * 
 * INFO:
 * http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#Cipher
 * 
 * @author Iztok Starc <iztok.starc@fri.uni-lj.si>
 * @date 19. 12. 2011
 * @version 1
 */


import java.security.*;
import java.util.Formatter;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class AsymmetricCipherExample {
    
    private static KeyPair kp;
    private static PublicKey pubKey;
    private static PrivateKey privKey;
    
    /**
     * ASYMMETRIC CIPHER ALGORITHM
     */
    public static String ALG1 = "RSA";
    
    /**
     * TEXT TO ENCRYPT/DECRYPT
     */
    public static String TEXT = "I would like to keep this text confidential Bob. Kind regards, Alice.";
    
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        
        /**
         * STEP 1.
         * Bob creates public and private key. Alice receives Bob's public key securely.
         */
        kp = KeyPairGenerator.getInstance(ALG1).generateKeyPair();
        privKey = kp.getPrivate();
        pubKey = kp.getPublic();
        
        /**
         * STEP 2.
         * Alice creates Cipher object defining cipher algorithm.
         * Alice encrypts clear-text and sends to Bob.
         */
        Cipher c1 = Cipher.getInstance(ALG1);
        c1.init(Cipher.ENCRYPT_MODE, pubKey);
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
         * Bob decrypts ciphertext using the same algorithm and his own
         * private key.
         */
        Cipher c2 = Cipher.getInstance(ALG1);
        c2.init(Cipher.DECRYPT_MODE, privKey);
        byte[] clear_TEXT = c2.doFinal(cipher_TEXT);
        
        /**
         * STEP 5.
         * Bob prints out clear-text.
         */
        System.out.println("[CLEARTEXT] " + new String(clear_TEXT));
        
    }
}
