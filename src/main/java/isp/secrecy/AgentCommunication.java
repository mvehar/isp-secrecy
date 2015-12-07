package isp.secrecy;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * I0->[I1]->A1->B1->A2->B2->A3->B3
 * <p/>
 * EXERCISE I1:
 * A communication channel is implemented with thread-safe blocking queue.
 * <p/>
 * Both agents are implemented by extending the Agents class,
 * creating anonymous class and overriding run(...) method.
 * <p/>
 * Both agents are started at the end of the main method definition below.
 * <p/>
 * Task:Study example.
 *
 * @author Iztok Starc <iztok.starc@fri.uni-lj.si>
 * @version 1
 * @date 12. 12. 2011
 */
public class AgentCommunication {

    private final static Logger LOG = Logger.getLogger(AgentCommunication.class.getCanonicalName());

    public static void main(String[] args) {

        /**
         * STEP 1.
         * Setup a insecure communication channel.
         */
        final BlockingQueue<String> alice2bob = new LinkedBlockingQueue<>();
        final BlockingQueue<String> bob2alice = new LinkedBlockingQueue<>();

        /**
         * STEP 2.
         * Agent Alice definition:
         * - uses the communication channel and 
         * - sends a message.
         */
        final Agent alice = new Agent(alice2bob, bob2alice, null, null, null, null) {
            @Override
            public void run() {
                try {
                    /**
                     * STEP 2.1
                     * Alice writes a message and sends to Bob.
                     * This action is recorded in Alice's log.
                     */
                    final String message = "I love you Bob. Kisses, Alice.";
                    outgoing.put(message);
                    LOG.info("[Alice]: Sending to Bob: " + message);
                } catch (InterruptedException e) {
                }
            }
        };

        /**
         * STEP 3.
         * Agent Bob definition:
         * - uses the communication channel and 
         * - receives the message.
         *
         * INFO: Java Anonymous Class
         * http://docstore.mik.ua/orelly/java-ent/jnut/ch03_12.htm
         */
        final Agent bob = new Agent(bob2alice, alice2bob, null, null, null, null) {

            @Override
            public void run() {
                try {
                    /**
                     * STEP 3.1
                     * Bob receives the message from Alice.
                     * This action is recorded in Bob's log.
                     */
                    final String message = incoming.take();
                    LOG.log(Level.INFO, "[Bob]: I have received: " + message);
                } catch (Exception ex) {
                }
            }
        };

        /**
         * STEP 4.
         * Agents are started
         */
        bob.start();
        alice.start();
    }
}
