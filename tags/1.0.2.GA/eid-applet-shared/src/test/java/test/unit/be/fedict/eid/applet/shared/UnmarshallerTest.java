/*
 * eID Applet Project.
 * Copyright (C) 2008-2009 FedICT.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

package test.unit.be.fedict.eid.applet.shared;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.LinkedList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.easymock.EasyMock;
import org.junit.Test;

import be.fedict.eid.applet.shared.AbstractProtocolMessage;
import be.fedict.eid.applet.shared.AppletProtocolMessageCatalog;
import be.fedict.eid.applet.shared.ClientEnvironmentMessage;
import be.fedict.eid.applet.shared.ErrorCode;
import be.fedict.eid.applet.shared.FinishedMessage;
import be.fedict.eid.applet.shared.IdentificationRequestMessage;
import be.fedict.eid.applet.shared.IdentityDataMessage;
import be.fedict.eid.applet.shared.annotation.HttpHeader;
import be.fedict.eid.applet.shared.annotation.MessageDiscriminator;
import be.fedict.eid.applet.shared.annotation.PostConstruct;
import be.fedict.eid.applet.shared.protocol.HttpReceiver;
import be.fedict.eid.applet.shared.protocol.ProtocolMessageCatalog;
import be.fedict.eid.applet.shared.protocol.Unmarshaller;

public class UnmarshallerTest {

	private static final Log LOG = LogFactory.getLog(UnmarshallerTest.class);

	@Test
	public void receiveIdentityDataMessageWithoutRequiredHeaders()
			throws Exception {
		// setup
		ProtocolMessageCatalog catalog = new AppletProtocolMessageCatalog();
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		HttpReceiver mockHttpReceiver = EasyMock.createMock(HttpReceiver.class);

		// stubs
		EasyMock.expect(mockHttpReceiver.isSecure()).andStubReturn(true);
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-Version"))
				.andStubReturn("1");
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-Type"))
				.andStubReturn("IdentityDataMessage");
		EasyMock.expect(mockHttpReceiver.getHeaderNames()).andStubReturn(
				new LinkedList<String>());
		EasyMock.expect(mockHttpReceiver.getBody()).andStubReturn(
				"hello world".getBytes());

		// prepare
		EasyMock.replay(mockHttpReceiver);

		// operate
		try {
			unmarshaller.receive(mockHttpReceiver);
			fail();
		} catch (RuntimeException e) {
			// expected input validation error
			// verify
			LOG.debug("expected exception: " + e.getMessage());
			EasyMock.verify(mockHttpReceiver);
		}
	}

	@Test
	public void receiveNoHeadersAtAll() throws Exception {
		// setup
		ProtocolMessageCatalog catalog = new AppletProtocolMessageCatalog();
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		HttpReceiver mockHttpReceiver = EasyMock.createMock(HttpReceiver.class);

		// stubs
		EasyMock.expect(mockHttpReceiver.isSecure()).andStubReturn(true);
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-Version"))
				.andStubReturn(null);

		// prepare
		EasyMock.replay(mockHttpReceiver);

		// operate
		try {
			unmarshaller.receive(mockHttpReceiver);
			fail();
		} catch (RuntimeException e) {
			// expected input validation error
			// verify
			LOG.debug("expected exception: " + e.getMessage());
			EasyMock.verify(mockHttpReceiver);
			assertFalse("null".equals(e.getMessage()));
		}
	}

	@Test
	public void receiveIdentityDataMessage() throws Exception {
		// setup
		ProtocolMessageCatalog catalog = new AppletProtocolMessageCatalog();
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		HttpReceiver mockHttpReceiver = EasyMock.createMock(HttpReceiver.class);

		// stubs
		EasyMock.expect(mockHttpReceiver.isSecure()).andStubReturn(true);
		List<String> testHeaderNames = new LinkedList<String>();
		testHeaderNames.add("foo-bar");
		testHeaderNames.add("X-AppletProtocol-Version");
		testHeaderNames.add("X-AppletProtocol-Type");
		testHeaderNames.add("X-AppletProtocol-IdentityFileSize");
		testHeaderNames.add("X-AppletProtocol-AddressFileSize");
		EasyMock.expect(mockHttpReceiver.getHeaderNames()).andStubReturn(
				testHeaderNames);
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-Version"))
				.andStubReturn("1");
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-Type"))
				.andStubReturn("IdentityDataMessage");
		EasyMock.expect(
				mockHttpReceiver
						.getHeaderValue("X-AppletProtocol-IdentityFileSize"))
				.andStubReturn("10");
		EasyMock.expect(
				mockHttpReceiver
						.getHeaderValue("X-AppletProtocol-AddressFileSize"))
				.andStubReturn("1");
		EasyMock.expect(mockHttpReceiver.getBody()).andStubReturn(
				"hello world".getBytes());

		// prepare
		EasyMock.replay(mockHttpReceiver);

		// operate
		Object result = unmarshaller.receive(mockHttpReceiver);

		// verify
		EasyMock.verify(mockHttpReceiver);

		assertNotNull(result);
		assertTrue(result instanceof IdentityDataMessage);
		IdentityDataMessage identityDataMessageResult = (IdentityDataMessage) result;
		assertNotNull(identityDataMessageResult.body);
		assertArrayEquals("hello world".getBytes(),
				identityDataMessageResult.body);
		assertEquals((Integer) 10, identityDataMessageResult.identityFileSize);
		assertEquals((Integer) 1, identityDataMessageResult.addressFileSize);
		assertArrayEquals("hello worl".getBytes(),
				identityDataMessageResult.idFile);
		assertArrayEquals("d".getBytes(), identityDataMessageResult.addressFile);
	}

	@Test
	public void receiveIdentificationRequestMessage() throws Exception {
		// setup
		ProtocolMessageCatalog catalog = new AppletProtocolMessageCatalog();
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		HttpReceiver mockHttpReceiver = EasyMock.createMock(HttpReceiver.class);

		// stubs
		EasyMock.expect(mockHttpReceiver.isSecure()).andStubReturn(true);
		List<String> testHeaderNames = new LinkedList<String>();
		testHeaderNames.add("foo-bar");
		testHeaderNames.add("X-AppletProtocol-Version");
		testHeaderNames.add("X-AppletProtocol-Type");
		testHeaderNames.add("X-AppletProtocol-IncludePhoto");
		EasyMock.expect(mockHttpReceiver.getHeaderNames()).andStubReturn(
				testHeaderNames);
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-Version"))
				.andStubReturn("1");
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-Type"))
				.andStubReturn("IdentificationRequestMessage");
		EasyMock.expect(
				mockHttpReceiver
						.getHeaderValue("X-AppletProtocol-IncludePhoto"))
				.andStubReturn("true");

		// prepare
		EasyMock.replay(mockHttpReceiver);

		// operate
		Object result = unmarshaller.receive(mockHttpReceiver);

		// verify
		EasyMock.verify(mockHttpReceiver);

		assertNotNull(result);
		assertTrue(result instanceof IdentificationRequestMessage);
		IdentificationRequestMessage message = (IdentificationRequestMessage) result;
		assertTrue(message.includePhoto);
	}

	@Test
	public void receiveFinishedMessage() throws Exception {
		// setup
		ProtocolMessageCatalog catalog = new AppletProtocolMessageCatalog();
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		HttpReceiver mockHttpReceiver = EasyMock.createMock(HttpReceiver.class);

		// stubs
		EasyMock.expect(mockHttpReceiver.isSecure()).andStubReturn(true);
		List<String> testHeaderNames = new LinkedList<String>();
		testHeaderNames.add("X-AppletProtocol-Version");
		testHeaderNames.add("X-AppletProtocol-Type");
		EasyMock.expect(mockHttpReceiver.getHeaderNames()).andStubReturn(
				testHeaderNames);
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-Version"))
				.andStubReturn("1");
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-Type"))
				.andStubReturn("FinishedMessage");

		// prepare
		EasyMock.replay(mockHttpReceiver);

		// operate
		Object result = unmarshaller.receive(mockHttpReceiver);

		// verify
		EasyMock.verify(mockHttpReceiver);

		assertNotNull(result);
		assertTrue(result instanceof FinishedMessage);
		FinishedMessage message = (FinishedMessage) result;
		assertNull(message.errorCode);
	}

	@Test
	public void receiveFinishedMessageWithErrorCode() throws Exception {
		// setup
		ProtocolMessageCatalog catalog = new AppletProtocolMessageCatalog();
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		HttpReceiver mockHttpReceiver = EasyMock.createMock(HttpReceiver.class);

		// stubs
		EasyMock.expect(mockHttpReceiver.isSecure()).andStubReturn(true);
		List<String> testHeaderNames = new LinkedList<String>();
		testHeaderNames.add("X-AppletProtocol-Version");
		testHeaderNames.add("X-AppletProtocol-Type");
		testHeaderNames.add("X-AppletProtocol-ErrorCode");
		EasyMock.expect(mockHttpReceiver.getHeaderNames()).andStubReturn(
				testHeaderNames);
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-Version"))
				.andStubReturn("1");
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-Type"))
				.andStubReturn("FinishedMessage");
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-ErrorCode"))
				.andStubReturn(ErrorCode.CERTIFICATE_EXPIRED.name());

		// prepare
		EasyMock.replay(mockHttpReceiver);

		// operate
		Object result = unmarshaller.receive(mockHttpReceiver);

		// verify
		EasyMock.verify(mockHttpReceiver);

		assertNotNull(result);
		assertTrue(result instanceof FinishedMessage);
		FinishedMessage message = (FinishedMessage) result;
		assertEquals(ErrorCode.CERTIFICATE_EXPIRED, message.errorCode);
	}

	public static final class MyRuntimeException extends RuntimeException {

		private static final long serialVersionUID = 1L;

		public MyRuntimeException(String message) {
			super(message);
		}
	}

	public static final class TestMessage extends AbstractProtocolMessage {

		@HttpHeader(TYPE_HTTP_HEADER)
		@MessageDiscriminator
		public static final String TYPE = TestMessage.class.getSimpleName();

		@PostConstruct
		public void postConstruct() {
			LOG.debug("postConstruct method invoked");
			throw new MyRuntimeException("failing post construct method");
		}
	}

	@Test
	public void testFailingPostConstructStackTrace() throws Exception {
		// setup
		ProtocolMessageCatalog catalog = new ProtocolMessageCatalog() {

			public List<Class<?>> getCatalogClasses() {
				List<Class<?>> catalogClasses = new LinkedList<Class<?>>();
				catalogClasses.add(TestMessage.class);
				return catalogClasses;
			}
		};
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		HttpReceiver mockHttpReceiver = EasyMock.createMock(HttpReceiver.class);

		// stubs
		EasyMock.expect(mockHttpReceiver.isSecure()).andStubReturn(true);
		List<String> testHeaderNames = new LinkedList<String>();
		testHeaderNames.add("foo-bar");
		testHeaderNames.add("X-AppletProtocol-Version");
		testHeaderNames.add("X-AppletProtocol-Type");
		EasyMock.expect(mockHttpReceiver.getHeaderNames()).andStubReturn(
				testHeaderNames);
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-Version"))
				.andStubReturn("1");
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-Type"))
				.andStubReturn(TestMessage.class.getSimpleName());

		// prepare
		EasyMock.replay(mockHttpReceiver);

		try {
			// operate
			unmarshaller.receive(mockHttpReceiver);
			fail();
		} catch (Exception e) {
			LOG.debug("error: " + e.getMessage(), e);
			// verify
			EasyMock.verify(mockHttpReceiver);
			assertTrue(e instanceof MyRuntimeException);
		}
	}

	@Test
	public void receiveClientEnvironmentMessage() throws Exception {
		// setup
		ProtocolMessageCatalog catalog = new AppletProtocolMessageCatalog();
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		HttpReceiver mockHttpReceiver = EasyMock.createMock(HttpReceiver.class);

		// stubs
		EasyMock.expect(mockHttpReceiver.isSecure()).andStubReturn(true);
		List<String> testHeaderNames = new LinkedList<String>();
		testHeaderNames.add("foo-bar");
		testHeaderNames.add("X-AppletProtocol-Version");
		testHeaderNames.add("X-AppletProtocol-Type");
		testHeaderNames.add("X-AppletProtocol-JavaVersion");
		testHeaderNames.add("X-AppletProtocol-JavaVendor");
		testHeaderNames.add("X-AppletProtocol-OSName");
		testHeaderNames.add("X-AppletProtocol-OSArch");
		testHeaderNames.add("X-AppletProtocol-OSVersion");
		EasyMock.expect(mockHttpReceiver.getHeaderNames()).andStubReturn(
				testHeaderNames);

		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-Version"))
				.andStubReturn("1");
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-Type"))
				.andStubReturn("ClientEnvironmentMessage");
		EasyMock
				.expect(
						mockHttpReceiver
								.getHeaderValue("X-AppletProtocol-JavaVersion"))
				.andStubReturn("1.6");
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-JavaVendor"))
				.andStubReturn("Sun");
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-OSName"))
				.andStubReturn("Linux");
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-OSArch"))
				.andStubReturn("i386");
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-OSVersion"))
				.andStubReturn("2.6");
		EasyMock.expect(mockHttpReceiver.getBody()).andStubReturn(
				"Reader 1\nReader 2\n".getBytes());

		// prepare
		EasyMock.replay(mockHttpReceiver);

		// operate
		Object result = unmarshaller.receive(mockHttpReceiver);

		// verify
		EasyMock.verify(mockHttpReceiver);

		assertNotNull(result);
		assertTrue(result instanceof ClientEnvironmentMessage);
		ClientEnvironmentMessage message = (ClientEnvironmentMessage) result;
		assertEquals("1.6", message.javaVersion);
		assertEquals("Sun", message.javaVendor);
		assertEquals("Linux", message.osName);
		assertEquals("i386", message.osArch);
		assertEquals("2.6", message.osVersion);
		// TODO body test
	}

	@Test
	public void receiveIdentityDataMessageCaseInsensitiveHeaders()
			throws Exception {
		// setup
		ProtocolMessageCatalog catalog = new AppletProtocolMessageCatalog();
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		HttpReceiver mockHttpReceiver = EasyMock.createMock(HttpReceiver.class);

		// stubs
		EasyMock.expect(mockHttpReceiver.isSecure()).andStubReturn(true);
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-Type"))
				.andStubReturn("IdentityDataMessage");

		List<String> testHeaderNames = new LinkedList<String>();
		testHeaderNames.add("foo-bar");
		testHeaderNames.add("x-appletprotocol-version");
		testHeaderNames.add("x-appletprotocol-type");
		testHeaderNames.add("x-appletprotocol-identityfilesize");
		testHeaderNames.add("x-appletprotocol-addressfilesize");
		EasyMock.expect(mockHttpReceiver.getHeaderNames()).andStubReturn(
				testHeaderNames);
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-Version"))
				.andStubReturn("1");
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("x-appletprotocol-version"))
				.andStubReturn("1");
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("x-appletprotocol-type"))
				.andStubReturn("IdentityDataMessage");
		EasyMock.expect(
				mockHttpReceiver
						.getHeaderValue("x-appletprotocol-identityfilesize"))
				.andStubReturn("10");
		EasyMock.expect(
				mockHttpReceiver
						.getHeaderValue("x-appletprotocol-addressfilesize"))
				.andStubReturn("1");
		EasyMock.expect(mockHttpReceiver.getBody()).andStubReturn(
				"hello world".getBytes());

		// prepare
		EasyMock.replay(mockHttpReceiver);

		// operate
		Object result = unmarshaller.receive(mockHttpReceiver);

		// verify
		EasyMock.verify(mockHttpReceiver);

		assertNotNull(result);
		assertTrue(result instanceof IdentityDataMessage);
		IdentityDataMessage identityDataMessageResult = (IdentityDataMessage) result;
		assertNotNull(identityDataMessageResult.body);
		assertArrayEquals("hello world".getBytes(),
				identityDataMessageResult.body);
		assertEquals((Integer) 10, identityDataMessageResult.identityFileSize);
		assertEquals((Integer) 1, identityDataMessageResult.addressFileSize);
	}

	@Test
	public void receiveUnknownMessage() throws Exception {
		// setup
		ProtocolMessageCatalog catalog = new AppletProtocolMessageCatalog();
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		HttpReceiver mockHttpReceiver = EasyMock.createMock(HttpReceiver.class);

		// stubs
		EasyMock.expect(mockHttpReceiver.isSecure()).andStubReturn(true);
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-Version"))
				.andStubReturn("1");
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-Type"))
				.andStubReturn("foo-bar");

		// prepare
		EasyMock.replay(mockHttpReceiver);

		// operate
		try {
			unmarshaller.receive(mockHttpReceiver);
			fail();
		} catch (RuntimeException e) {
			// expected
			// verify
			LOG.debug("expected error: " + e.getMessage());
			EasyMock.verify(mockHttpReceiver);
		}
	}

	@Test
	public void unsecureHttpReceiver() throws Exception {
		// setup
		ProtocolMessageCatalog catalog = new AppletProtocolMessageCatalog();
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		HttpReceiver mockHttpReceiver = EasyMock.createMock(HttpReceiver.class);

		// stubs
		EasyMock.expect(mockHttpReceiver.isSecure()).andStubReturn(false);

		// prepare
		EasyMock.replay(mockHttpReceiver);

		// operate
		try {
			unmarshaller.receive(mockHttpReceiver);
			fail();
		} catch (SecurityException e) {
			// expected
			// verify
			LOG.debug("expected error: " + e.getMessage());
			EasyMock.verify(mockHttpReceiver);
		}
	}

	@Test
	public void protocolVersion() throws Exception {
		// setup
		ProtocolMessageCatalog catalog = new AppletProtocolMessageCatalog();
		Unmarshaller unmarshaller = new Unmarshaller(catalog);

		HttpReceiver mockHttpReceiver = EasyMock.createMock(HttpReceiver.class);

		// stubs
		EasyMock.expect(mockHttpReceiver.isSecure()).andStubReturn(true);
		EasyMock.expect(
				mockHttpReceiver.getHeaderValue("X-AppletProtocol-Version"))
				.andStubReturn("007");

		// prepare
		EasyMock.replay(mockHttpReceiver);

		// operate
		try {
			unmarshaller.receive(mockHttpReceiver);
			fail();
		} catch (RuntimeException e) {
			// expected
			// verify
			LOG.debug("expected error: " + e.getMessage());
			EasyMock.verify(mockHttpReceiver);
		}
	}

	// TODO: test semantical validator

}