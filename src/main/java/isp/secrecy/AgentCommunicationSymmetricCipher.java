package isp.secrecy; /**
 * I0->I1->A1->B1->A2->B2->A3->B3->A4->B4->A5->[B5]
 * 
 * EXERCISE B5:
 * An agent communication example. Message confidentiality is provided using
 * symmetric cipher algorithm.
 * 
 * Special care has to be taken when transferring binary stream over the communication
 * channel, thus, Base64 encoding/decoding is used to transfer checksums.
 * 
 * A communication channel is implemented by thread-safe blocking queue using
 * linked-list data structure.
 * 
 * Both agent behavior are implemented by extending Agents class and
 * creating anonymous class and overriding run(...) method.
 * 
 * Both agents are "fired" at the end of the main method definition below.
 * 
 * EXERCISE:
 * - Study this example.
 * - Observe what happens if Alice's transmitter is corrupted?
 * - Observe both signatures in hexadecimal format (use Formatter).
 * 
 * - Alice and Bob would like to communicate securely, i.e. /w confidentiality and 
 *   integrity security properties enabled. Provide message authentication code
 *   facility in order to enable message integrity. You should use separate keys for
 *   encryption and MAC.
 * 
 * INFO:
 * http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#Cipher
 * 
 * @author Iztok Starc <iztok.starc@fri.uni-lj.si>
 * @date 12. 12. 2011
 * @version 1
 */


import java.security.*;
import javax.crypto.*;
import java.util.concurrent.*;
import java.util.Formatter;

public class AgentCommunicationSymmetricCipher {
    
    /**
     * Standard Algorithm Names
     * http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html
     */
    
    /**
     * BLOCK CIPHER
     */
    public static String[] ALG1 = {"DES","DES/ECB/PKCS5Padding"};
    public static String[] ALG2 = {"DESede","DESede/ECB/PKCS5Padding"};
    public static String[] ALG3 = {"AES","AES/ECB/PKCS5Padding"};
    public static String[] ALG4 = {"AES","AES/CBC/PKCS5Padding"};
    
    /**
     * STREAM CIPHER
     */
    public static String[] ALG5 = {"RC4","RC4"};
  
    private static Agent alice;
    private static Agent bob;
    
    private static BlockingQueue<String> alice2bob;
    private static BlockingQueue<String> bob2alice;

    public static void main(String[] args) throws NoSuchAlgorithmException {
        
        /**
         * STEP 1.
         * Alice and Bob agree upon a cipher algorithm and a shared secret session key 
         * is created that will be used for encryption and decryption.
         */
        Key symkey = KeyGenerator.getInstance(ALG3[0]).generateKey();
        
        /**
         * STEP 2.
         * Setup a (un)secure communication channel.
         */
        AgentCommunicationSymmetricCipher.alice2bob = new LinkedBlockingQueue<String>();
        AgentCommunicationSymmetricCipher.bob2alice = new LinkedBlockingQueue<String>();
        
        /**
         * STEP 3.
         * Agent Alice definition:
         * - uses the communication channel,
         * - sends a message that is comprised of:
         *   o cipher_TEXT
         * - uses shared secret key to encrypt clear_TEXT.
         */
        alice = new Agent(bob2alice,alice2bob,symkey,ALG3[1]) {
            
            @Override
            public void run() {
                try {                  
                    /**
                     * STEP 3.1
                     * Alice writes a message.
                     * This action is recorded in Alice's log.
                     */
                    String TEXT = "I love you Bob. Kisses, Alice.";
                    System.out.println("[Alice::Log]: I have sent the following message to Bob.");
                    System.out.println("[Alice::Log]: TEXT: " + TEXT);
                    
                    /**
                     * STEP 3.2
                     * In addition, Alice encrypts clear_TEXT using selected
                     * algorithm and shared secret key.
                     */
                    Cipher c1 = Cipher.getInstance(super.cryptoAlgorithm);
                    c1.init(Cipher.ENCRYPT_MODE, super.cryptoKey);
                    byte[] cipher_TEXT = c1.doFinal(TEXT.getBytes());
                    
                    /**
                     * STEP 3.3
                     * Special care has to be taken when transferring binary stream 
                     * over the communication channel, thus, 
                     * Base64 encoding/decoding is used to transfer checksums.
                     */
                    super.toAgent.put(Base64.encode(cipher_TEXT));
                    
                    //KOS
                    
                } catch (Exception ex) {
                    System.out.println("[Alice::Log]: Something went wrong.");
                }
            }
        };
        
        /**
         * STEP 4.
         * Agent Bob definition:
         * - uses the communication channel,
         * - receives the message that is comprised of:
         *   o cipher_TEXT
         * - uses shared secret key to decrypt the cipher_TEXT
         */
        bob = new Agent(alice2bob,bob2alice,symkey,ALG3[1]){
            
            @Override
            public void run() {
                try {
                    System.out.println("[Bob::Log]: I am waiting for message.");
                    /**
                     * STEP 4.1
                     * Special care has to be taken when transferring binary stream 
                     * over the communication channel, thus, 
                     * Base64 encoding/decoding is used to transfer checksums.
                     */
                    byte[] received_cipher_TEXT = Base64.decode(super.fromAgent.take()); /* */
                    Formatter frm1 = new Formatter();
                    for (byte b : received_cipher_TEXT)
                        frm1.format("%02x", b);
                    System.out.println("[Bob::Log]: CIPHERTEXT: " + frm1.toString());
                    //received_cipher_TEXT[10] = (byte) 'x';
                    /**
                     * STEP 4.3
                     * Bob decrypts cipher_TEXT.
                     */
                    Cipher c1 = Cipher.getInstance(super.cryptoAlgorithm);
                    c1.init(Cipher.DECRYPT_MODE, super.cryptoKey);
                    byte[] received_clear_TEXT = c1.doFinal(received_cipher_TEXT);
                    
                    /**
                     * STEP 4.4
                     * Print out.
                     */
                    System.out.println("[Bob::Log]: CLEARTEXT: " + new String(received_clear_TEXT));
                    
                    // KOS
                               
                } catch (Exception ex) {
                    System.out.println("[Bob::Log]: Something went wrong.");
                }
            }
        };
        
        /**
         * STEP 5.
         * Two commands below "fire" both agents and the fun begins ... :-)
         */
        alice.start();
        bob.start();
    }
}
