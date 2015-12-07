package isp.secrecy; /**
 * I0->I1->A1->B1->A2->B2->A3->B3->A4->B4->A5->[B5]
 * <p/>
 * EXERCISE B5:
 * An agent communication example. Message confidentiality is provided using
 * symmetric cipher algorithm.
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
 * - Observe cipher texts in hexadecimal
 * <p/>
 * - Alice and Bob would like to communicate securely, i.e. /w confidentiality and
 * integrity security properties enabled. Provide message authentication code
 * facility in order to enable message integrity. You should use separate keys for
 * encryption and MAC.
 * - Provide Authenticated Encryption using the built in GCM mode
 * <p/>
 * INFO:
 * http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#Cipher
 *
 * @author Iztok Starc <iztok.starc@fri.uni-lj.si>
 * @date 12. 12. 2011
 * @version 1
 */

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.xml.bind.DatatypeConverter;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class AgentCommunicationSymmetricCipher {
    // BLOCK CIPHER
    public static String[] ALG1 = { "DES", "DES/ECB/PKCS5Padding" };
    public static String[] ALG2 = { "DESede", "DESede/ECB/PKCS5Padding" };
    public static String[] ALG3 = { "AES", "AES/ECB/PKCS5Padding" };
    public static String[] ALG4 = { "AES", "AES/CBC/PKCS5Padding" };

    // STREAM CIPHER
    public static String[] ALG5 = { "RC4", "RC4" };

    public static void main(String[] args) throws NoSuchAlgorithmException {
        /**
         * STEP 1.
         * Alice and Bob agree upon a cipher algorithm and a shared secret session key 
         * is created that will be used for encryption and decryption.
         */
        final Key key = KeyGenerator.getInstance(ALG4[0]).generateKey();

        /**
         * STEP 2.
         * Setup an insecure communication channel.
         */
        final BlockingQueue<String> alice2bob = new LinkedBlockingQueue<>();
        final BlockingQueue<String> bob2alice = new LinkedBlockingQueue<>();

        // TODO STEP 3: Alice creates, encrypts and sends a message
        // In some modes, you have to encode and send the algorithm parameters as well
        final Agent alice = new Agent(alice2bob, bob2alice, key, ALG4[1], null, null) {

            @Override
            public void run() {
                try {
                    final String message = "I love you Bob. Kisses, Alice.";
                    System.out.println("[Alice] Message: " + message);

                    final byte[] clearText = message.getBytes("UTF-8");
                    final Cipher cipher = Cipher.getInstance(this.cryptoAlgorithm);
                    cipher.init(Cipher.ENCRYPT_MODE, this.cryptoKey);
                    final AlgorithmParameters ap = cipher.getParameters();
                    //patrametrs
                    final byte[] parametrsText = ap.getEncoded();
                    final String parametersString = DatatypeConverter.printHexBinary(parametrsText);

                    final byte[] cipherText = cipher.doFinal(clearText);
                    final String cipherString = DatatypeConverter.printHexBinary(cipherText);

                    //send out
                    outgoing.put(parametersString);
                    outgoing.put(cipherString);

                } catch (Exception ex) {
                    System.out.println("[Alice] Exception: " + ex.getLocalizedMessage());
                }
            }
        };

        // TODO STEP 4: Bob receives, decrypts and displays a message
        final Agent bob = new Agent(bob2alice, alice2bob, key, ALG4[1], null, null) {
            @Override
            public void run() {
                try {
                    // TODO
                    final String parametersString = incoming.take();
                    final String cipherString = incoming.take();

                    final byte[] parametersHEX  =DatatypeConverter.parseHexBinary(parametersString);
                    final byte[] cipherHEX = DatatypeConverter.parseHexBinary(cipherString);

                    //Parametrs init
                    final AlgorithmParameters ap = AlgorithmParameters.getInstance("AES");
                    ap.init(parametersHEX);

                    final Cipher cipher2 = Cipher.getInstance(this.cryptoAlgorithm);
                    cipher2.init(Cipher.DECRYPT_MODE, this.cryptoKey, ap);

                    final byte[] decryptedText = cipher2.doFinal(cipherHEX);

                    System.out.println("[Bob]: Received from Alice: Parameters: " + parametersString);
                    System.out.println("[Bob]: Received from Alice: EncString: " + cipherString);
                    System.out.println("[Bob]: Received from Alice: Original: " + new String(decryptedText));

                } catch (Exception ex) {
                    System.out.println("[Bob] Exception: " + ex.getLocalizedMessage());
                }
            }
        };

        alice.start();
        bob.start();
    }
}
