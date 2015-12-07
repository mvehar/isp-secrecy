package isp.secrecy;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * I0->I1->A1->B1->A2->B2->A3->B3->A4->[B4]
 * <p/>
 * EXERCISE B4:
 * An agent communication example. Message Confidentiality is provided using asymmetric
 * cypher algorithm.
 *
 * IMPORTANT: This is an insecure example. One should never encrypt with a TDF (such as RSA) directly.
 * Such construction is deterministic and many known attacks against it exist.
 * <p/>
 * Special care has to be taken when transferring binary data over the string-based communication
 * channel, therefore we convert byte array into String of hexadecimal characters.
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
 * - Observe both ciphertext in hexadecimal format
 * - HW: Mount a man in the middle attack and try to figure out the contents of the message
 * <p/>
 * INFO:
 * http://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#Cipher
 *
 * @author Iztok Starc <iztok.starc@fri.uni-lj.si>
 * @version 1
 * @date 19. 12. 2011
 */

public class AgentCommunicationAsymmetricCipher {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        final String encryptionAlg = "RSA";

        /**
         * STEP 1.
         * Bob creates his key pair and public and private key. Alice receives Bob's public key securely.
         */
        final KeyPair bobKP = KeyPairGenerator.getInstance(encryptionAlg).generateKeyPair();

        /**
         * STEP 2.
         * Setup an insecure communication channel.
         */
        final BlockingQueue<String> alice2bob = new LinkedBlockingQueue<>();
        final BlockingQueue<String> bob2alice = new LinkedBlockingQueue<>();

        /**
         * STEP 3.
         * Alice:
         * - creates a message,
         * - encrypts it using Bob's public key
         * - sends it to Bob
         */
        final Agent alice = new Agent(alice2bob, bob2alice, bobKP.getPublic(), encryptionAlg, null, null) {
            @Override
            public void run() {
                try {
                    // STEP 3.1:  Alice creates a message
                    final String text = "I love you Bob. Kisses, Alice.";

                    // TODO STEP 3.2: Alice encrypts the text with selected algorithm using Bob's public key.


                    // TODO STEP 3.3: Encode the cipher text into string of hexadecimal numbers


                    // TODO STEP 3.4: Alice logs the act of sending the message

                    // TODO STEP 3.4: Send the message across the channel
                } catch (Exception ex) {
                    System.err.println("[Alice] Exception: " + ex.getMessage());
                }
            }
        };

        /**
         * STEP 4.
         * Bob:
         * - waits for a message from Alice
         * - upon receiving it, uses his private key to decrypt it
         */
        final Agent bob = new Agent(bob2alice, alice2bob, bobKP.getPrivate(), encryptionAlg, null, null) {
            @Override
            public void run() {
                try {
                    // STEP 4.1: Bob receives the message
                    final String cipherTextHEX = incoming.take();
                    System.out.println("[Bob]: Received " + cipherTextHEX);

                    // TODO STEP 4.2: Decode the incoming string of HEX literals into a byte array

                    // TODO STEP 4.3: Bob decrypts the cipher text

                    // TODO STEP 4.3: Bob creates a string from the decrypted byte array

                    // TODO STEP 4.4: Bob displays the text
                } catch (Exception ex) {
                    System.out.println("[Bob]: Exception: " + ex.getLocalizedMessage());
                }
            }
        };

        alice.start();
        bob.start();
    }
}
