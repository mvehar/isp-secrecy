package isp.secrecy; /**
 * [I0]->I1->A1->B1->A2->B2->A3->B3
 * <p/>
 * EXERCISE I0: Make sure you understand this example.
 *
 * @author Iztok Starc <iztok.starc@fri.uni-lj.si>
 * @date 26. 11. 2015
 * @version 1
 */

import java.security.Key;
import java.util.concurrent.BlockingQueue;

/**
 * Represents an agent that can communicate with other agents using
 * ideal communication channel.
 * <p/>
 * Agent's behavior is implemented by extending Agents class and
 * overriding run(...) method.
 */
public abstract class Agent extends Thread {
    protected final BlockingQueue<String> outgoing, incoming;

    protected final Key macKey, cryptoKey;
    protected final String cryptoAlgorithm, macAlgorithm;

    public Agent(final BlockingQueue<String> outgoing, final BlockingQueue<String> incoming, final Key cryptoKey,
                 final String cryptoAlgorithm, final Key macKey, final String macAlgorithm) {
        this.outgoing = outgoing;
        this.incoming = incoming;
        this.cryptoKey = cryptoKey;
        this.cryptoAlgorithm = cryptoAlgorithm;
        this.macKey = macKey;
        this.macAlgorithm = macAlgorithm;
    }
}
