package test.be.fedict.eid.applet;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.URL;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jgroups.Address;
import org.jgroups.JChannel;
import org.jgroups.Message;
import org.jgroups.Receiver;
import org.jgroups.View;
import org.junit.Test;

public class JGroupsSpikeTest {

	// /udp_fedict.xml
	
	@Test
	public void testJGroupsSingleAgent() throws Exception {
		// setup
		JChannel channel;
		if (true) {
			URL udpFedictConfig = JGroupsSpikeTest.class
					.getResource("/udp.xml");
			assertNotNull(udpFedictConfig);
			channel = new JChannel(udpFedictConfig);
		} else {
			channel = new JChannel();
		}
		MyReceiver myReceiver = new MyReceiver("Hello World");
		channel.setReceiver(myReceiver);
		channel.connect("hello-world");

		// operate
		channel.send(new Message(null, null, "Hello World"));
		channel.close();

		// verify
		assertTrue(myReceiver.hasExpectedMessageReceived());
	}

	public static final class MyReceiver implements Receiver {

		private static final Log LOG = LogFactory.getLog(MyReceiver.class);

		private final String expectedMessage;

		private boolean expectedMessageReceived;

		public MyReceiver(String expectedMessage) {
			this.expectedMessage = expectedMessage;
			this.expectedMessageReceived = false;
		}

		@Override
		public void receive(Message msg) {
			Address srcAddress = msg.getSrc();
			Object object = msg.getObject();
			LOG.debug("receiving from " + srcAddress + " message " + object);
			LOG.debug("message object type: " + object.getClass().getName());
			if (this.expectedMessage.equals(object)) {
				this.expectedMessageReceived = true;
			}
		}

		public boolean hasExpectedMessageReceived() {
			return this.expectedMessageReceived;
		}

		@Override
		public byte[] getState() {
			LOG.debug("getState");
			return null;
		}

		@Override
		public void setState(byte[] state) {
			LOG.debug("setState");
		}

		@Override
		public void block() {
			LOG.debug("block");
		}

		@Override
		public void suspect(Address address) {
			LOG.debug("suspect: " + address);
		}

		@Override
		public void viewAccepted(View view) {
			LOG.debug("view accepted: " + view);
		}
	}
}
