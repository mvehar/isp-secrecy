package isp.secrecy;

import javax.crypto.Cipher;
import java.security.*;
import java.util.Formatter;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * I0->I1->A1->B1->A2->B2->A3->B3->A4->[B4]
 * <p/>
 * EXERCISE B4:
 * An agent communication example. Message Confidentiality is provided using asymmetric
 * cypher algorithm.
 * <p/>
 * Special care has to be taken when transferring binary stream over the communication
 * channel, thus, Base64 encoding/decoding is used to transfer checksums.
 * <p/>
 * A communication channel is implemented by thread-safe blocking queue using
 * linked-list data structure.
 * <p/>
 * Both agent behavior are implemented by extending Agents class and
 * creating anonymous class and overriding run(...) method.
 * <p/>
 * Both agents are "fired" at the end of the main method definition below.
 * <p/>
 * EXERCISE:
 * - Study this example.
 * - Observe both ciphertext in hexadecimal format (use Formatter).
 * <p/>
 * INFO:
 * http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#Cipher
 *
 * @author Iztok Starc <iztok.starc@fri.uni-lj.si>
 * @version 1
 * @date 19. 12. 2011
 */


public class AgentCommunicationAsymmetricCipher {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        /**
         * STEP 1.
         * Bob creates public and private key. Alice receives Bob's public key securely.
         */

        final String encryptionAlgorithm = "RSA";

        final KeyPair kp = KeyPairGenerator.getInstance(encryptionAlgorithm).generateKeyPair();
        final PrivateKey privKey = kp.getPrivate();
        final PublicKey pubKey = kp.getPublic();

        /**
         * STEP 2.
         * Setup a (un)secure communication channel.
         */
        final BlockingQueue<String> alice2bob = new LinkedBlockingQueue<String>();
        final BlockingQueue<String> bob2alice = new LinkedBlockingQueue<String>();

        /**
         * STEP 3.
         * Agent Alice definition:
         * - uses the communication channel,
         * - sends a message that is comprised of:
         *   o cipher_TEXT
         * - uses Bob's private key to encrypt clear_TEXT.
         */
        final Agent alice = new Agent(bob2alice, alice2bob, (Key) pubKey, encryptionAlgorithm) {

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
                     * algorithm and Bob's public key.
                     */
                    Cipher c1 = Cipher.getInstance(super.cryptoAlgorithm);
                    c1.init(Cipher.ENCRYPT_MODE, (PublicKey) super.cryptoKey);
                    byte[] cipher_TEXT = c1.doFinal(TEXT.getBytes());

                    /**
                     * STEP 3.3
                     * Special care has to be taken when transferring binary stream 
                     * over the communication channel, thus, 
                     * Base64 encoding/decoding is used to transfer checksums.
                     */
                    super.outgoing.put(Base64.encode(cipher_TEXT));

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
         * - uses his private key to decrypt the cipher_TEXT
         */
        final Agent bob = new Agent(alice2bob, bob2alice, (Key) privKey, encryptionAlgorithm) {

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
                    byte[] received_cipher_TEXT = Base64.decode(super.incoming.take()); /* */
                    Formatter frm1 = new Formatter();
                    for (byte b : received_cipher_TEXT)
                        frm1.format("%02x", b);
                    System.out.println("[Bob::Log]: CIPHERTEXT: " + frm1.toString());

                    /**
                     * STEP 4.3
                     * Bob decrypts cipher_TEXT.
                     */
                    Cipher c1 = Cipher.getInstance(super.cryptoAlgorithm);
                    c1.init(Cipher.DECRYPT_MODE, (PrivateKey) super.cryptoKey);
                    byte[] received_clear_TEXT = c1.doFinal(received_cipher_TEXT);

                    /**
                     * STEP 4.4
                     * Print out.
                     */
                    System.out.println("[Bob::Log]: CLEARTEXT: " + new String(received_clear_TEXT));

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
