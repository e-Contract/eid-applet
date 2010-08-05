package test.be.fedict.eid.applet;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.URL;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jgroups.Address;
import org.jgroups.ChannelClosedException;
import org.jgroups.ChannelException;
import org.jgroups.ChannelNotConnectedException;
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

	private static final int AGENT_COUNT = 1;

	@Test
	public void testJGroupsAgents() throws Exception {
		RunnableReceiver[] agents = new RunnableReceiver[AGENT_COUNT];
		AgentContext context = new AgentContext();
		for (int idx = 0; idx < agents.length; idx++) {
			RunnableReceiver agent = new RunnableReceiver("/udp.xml",
					"channel-name", context, idx);
			agent.start();
			agents[idx] = agent;
		}

		String msg = "hello world";
		agents[0].sendMessage(msg);
		context.waitForReceivedMessage(msg, AGENT_COUNT);

		for (RunnableReceiver agent : agents) {
			agent.stop();
		}
	}

	public static class AgentContext {

		private final Map<String, Set<Integer>> receivedMessages;

		public AgentContext() {
			this.receivedMessages = new HashMap<String, Set<Integer>>();
		}

		public void waitForReceivedMessage(String msg, int agentCount)
				throws InterruptedException {
			synchronized (this) {
				while (true) {
					Set<Integer> agentIds = this.receivedMessages.get(msg);
					if (null != agentIds) {
						if (agentCount == agentIds.size()) {
							return;
						}
					}
					this.wait();
				}
			}
		}

		public synchronized void notifyReceivedMessage(int agentId,
				String message) {
			Set<Integer> agentIds = this.receivedMessages.get(message);
			if (null == agentIds) {
				agentIds = new HashSet<Integer>();
			}
			this.receivedMessages.put(message, agentIds);
			agentIds.add(agentId);
			this.notify();
		}
	}

	public static class RunnableReceiver implements Receiver, Runnable {

		private static final Log LOG = LogFactory
				.getLog(RunnableReceiver.class);

		private final String jgroupsConfigResourceName;

		private final String channelName;

		private final AgentContext context;

		private final int agentId;

		private boolean running;

		private Thread thread;

		private final List<String> outgoingMessages;

		private boolean ready;
		
		public RunnableReceiver(String jgroupsConfigResourceName,
				String channelName, AgentContext context, int agentId) {
			this.jgroupsConfigResourceName = jgroupsConfigResourceName;
			this.channelName = channelName;
			this.outgoingMessages = new LinkedList<String>();
			this.context = context;
			this.agentId = agentId;
		}

		public void sendMessage(String message) {
			synchronized (this) {
				LOG.debug("agent " + this.agentId
						+ ": queing message for sending :" + message);
				this.outgoingMessages.add(message);
				this.notify();
			}
		}
		
		

		@Override
		public void receive(Message msg) {
			Address srcAddress = msg.getSrc();
			Object object = msg.getObject();
			LOG.debug("receiving from " + srcAddress + " message " + object);
			this.context.notifyReceivedMessage(this.agentId, object.toString());
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

		public void stop() throws InterruptedException {
			this.running = false;
			synchronized (this) {
				this.notify();
			}
			this.thread.join();
			this.thread = null;
		}

		public void start() {
			if (null != this.thread) {
				throw new IllegalStateException("already started");
			}
			this.thread = new Thread(this);
			this.thread.start();
		}

		@Override
		public void run() {
			LOG.debug("run");
			this.running = true;
			JChannel channel;
			URL udpFedictConfig = RunnableReceiver.class
					.getResource(this.jgroupsConfigResourceName);
			try {
				channel = new JChannel(udpFedictConfig);
			} catch (ChannelException e) {
				throw new RuntimeException("JGroups channel exception: "
						+ e.getMessage(), e);
			}
			channel.setReceiver(this);
			try {
				channel.connect(this.channelName);
			} catch (ChannelException e) {
				throw new RuntimeException(
						"JGroups channel connect exception: " + e.getMessage(),
						e);
			}
			LOG.debug("connected to channel");
			while (this.running) {
				synchronized (this) {
					try {
						this.ready = true;
						this.wait();
					} catch (InterruptedException e) {
						throw new RuntimeException("wait error: "
								+ e.getMessage(), e);
					}
					LOG.debug("agent " + this.agentId + ": waking up");
					if (false == this.running) {
						channel.close();
						break;
					}
					while (false == this.outgoingMessages.isEmpty()) {
						String message = this.outgoingMessages.remove(0);
						LOG.debug("agent " + this.agentId
								+ ": sending message: " + message);
						try {
							channel.send(new Message(null, null, message));
						} catch (ChannelNotConnectedException e) {
							throw new RuntimeException(
									"channel not connected: " + e.getMessage(),
									e);
						} catch (ChannelClosedException e) {
							throw new RuntimeException("channel closed: "
									+ e.getMessage(), e);
						}
					}
				}
			}
		}
	}
}
