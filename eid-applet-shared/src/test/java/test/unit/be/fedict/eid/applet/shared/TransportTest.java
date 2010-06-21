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

import static org.junit.Assert.fail;

import java.util.LinkedList;

import org.easymock.EasyMock;
import org.junit.Test;

import be.fedict.eid.applet.shared.ClientEnvironmentMessage;
import be.fedict.eid.applet.shared.ErrorCode;
import be.fedict.eid.applet.shared.FinishedMessage;
import be.fedict.eid.applet.shared.IdentificationRequestMessage;
import be.fedict.eid.applet.shared.IdentityDataMessage;
import be.fedict.eid.applet.shared.protocol.HttpTransmitter;
import be.fedict.eid.applet.shared.protocol.Transport;

public class TransportTest {

	@Test
	public void transmitIdentityDataMessage() throws Exception {
		// setup
		IdentityDataMessage identityDataMessage = new IdentityDataMessage();
		identityDataMessage.identityFileSize = 20;
		identityDataMessage.addressFileSize = 10;
		identityDataMessage.body = "hello world".getBytes();

		HttpTransmitter mockHttpTransmitter = EasyMock
				.createMock(HttpTransmitter.class);

		// expectations
		EasyMock.expect(mockHttpTransmitter.isSecure()).andReturn(true);
		mockHttpTransmitter.addHeader("X-AppletProtocol-Version", "1");
		mockHttpTransmitter.addHeader("X-AppletProtocol-Type",
				"IdentityDataMessage");
		mockHttpTransmitter
				.addHeader("X-AppletProtocol-IdentityFileSize", "20");
		mockHttpTransmitter.addHeader("X-AppletProtocol-AddressFileSize", "10");
		byte[] body = "hello world".getBytes();
		mockHttpTransmitter.setBody(EasyMock.aryEq(body));
		mockHttpTransmitter.addHeader("Content-Length", Integer
				.toString(body.length));

		// prepare
		EasyMock.replay(mockHttpTransmitter);

		// operate
		Transport.transfer(identityDataMessage, mockHttpTransmitter);

		// verify
		EasyMock.verify(mockHttpTransmitter);
	}

	@Test
	public void transmitFinishedMessage() throws Exception {
		// setup
		FinishedMessage finishedMessage = new FinishedMessage();

		HttpTransmitter mockHttpTransmitter = EasyMock
				.createMock(HttpTransmitter.class);

		// expectations
		EasyMock.expect(mockHttpTransmitter.isSecure()).andReturn(true);
		mockHttpTransmitter.addHeader("X-AppletProtocol-Version", "1");
		mockHttpTransmitter.addHeader("X-AppletProtocol-Type",
				"FinishedMessage");
		mockHttpTransmitter.addHeader("Content-Length", "0");

		// prepare
		EasyMock.replay(mockHttpTransmitter);

		// operate
		Transport.transfer(finishedMessage, mockHttpTransmitter);

		// verify
		EasyMock.verify(mockHttpTransmitter);
	}

	@Test
	public void transmitFinishedMessageWithErrorCode() throws Exception {
		// setup
		FinishedMessage finishedMessage = new FinishedMessage(
				ErrorCode.CERTIFICATE_EXPIRED);

		HttpTransmitter mockHttpTransmitter = EasyMock
				.createMock(HttpTransmitter.class);

		// expectations
		EasyMock.expect(mockHttpTransmitter.isSecure()).andReturn(true);
		mockHttpTransmitter.addHeader("X-AppletProtocol-Version", "1");
		mockHttpTransmitter.addHeader("X-AppletProtocol-Type",
				"FinishedMessage");
		mockHttpTransmitter.addHeader("X-AppletProtocol-ErrorCode",
				ErrorCode.CERTIFICATE_EXPIRED.name());
		mockHttpTransmitter.addHeader("Content-Length", "0");

		// prepare
		EasyMock.replay(mockHttpTransmitter);

		// operate
		Transport.transfer(finishedMessage, mockHttpTransmitter);

		// verify
		EasyMock.verify(mockHttpTransmitter);
	}

	@Test
	public void transmitIdentificationRequestMessage() throws Exception {
		// setup
		IdentificationRequestMessage message = new IdentificationRequestMessage();
		message.includePhoto = true;

		HttpTransmitter mockHttpTransmitter = EasyMock
				.createMock(HttpTransmitter.class);

		// expectations
		EasyMock.expect(mockHttpTransmitter.isSecure()).andReturn(true);
		mockHttpTransmitter.addHeader("X-AppletProtocol-Version", "1");
		mockHttpTransmitter.addHeader("X-AppletProtocol-Type",
				"IdentificationRequestMessage");
		mockHttpTransmitter.addHeader("X-AppletProtocol-IncludeAddress",
				"false");
		mockHttpTransmitter.addHeader("X-AppletProtocol-IncludePhoto", "true");

		// TODO: protocol optimization: next could be omitted
		mockHttpTransmitter.addHeader("X-AppletProtocol-IncludeIntegrityData",
				"false");
		mockHttpTransmitter.addHeader("X-AppletProtocol-IncludeCertificates",
				"false");
		mockHttpTransmitter.addHeader("X-AppletProtocol-RemoveCard", "false");
		mockHttpTransmitter.addHeader("Content-Length", "0");

		// prepare
		EasyMock.replay(mockHttpTransmitter);

		// operate
		Transport.transfer(message, mockHttpTransmitter);

		// verify
		EasyMock.verify(mockHttpTransmitter);
	}

	@Test
	public void transmitClientEnvironmentMessage() throws Exception {
		// setup
		ClientEnvironmentMessage message = new ClientEnvironmentMessage();
		message.javaVersion = "1.6";
		message.javaVendor = "Sun";
		message.osName = "Linux";
		message.osArch = "i386";
		message.osVersion = "2.6";
		message.readerList = new LinkedList<String>();
		message.readerList.add("Reader 1");
		message.readerList.add("Reader 2");

		HttpTransmitter mockHttpTransmitter = EasyMock
				.createMock(HttpTransmitter.class);

		// expectations
		EasyMock.expect(mockHttpTransmitter.isSecure()).andReturn(true);
		mockHttpTransmitter.addHeader("X-AppletProtocol-Version", "1");
		mockHttpTransmitter.addHeader("X-AppletProtocol-Type",
				"ClientEnvironmentMessage");

		mockHttpTransmitter.addHeader("X-AppletProtocol-JavaVersion", "1.6");
		mockHttpTransmitter.addHeader("X-AppletProtocol-JavaVendor", "Sun");
		mockHttpTransmitter.addHeader("X-AppletProtocol-OSName", "Linux");
		mockHttpTransmitter.addHeader("X-AppletProtocol-OSArch", "i386");
		mockHttpTransmitter.addHeader("X-AppletProtocol-OSVersion", "2.6");
		String lineSeparator = System.getProperty("line.separator");
		byte[] body = ("Reader 1" + lineSeparator + "Reader 2" + lineSeparator)
				.getBytes();
		mockHttpTransmitter.setBody(EasyMock.aryEq(body));
		mockHttpTransmitter.addHeader("Content-Length", Integer
				.toString(body.length));

		// prepare
		EasyMock.replay(mockHttpTransmitter);

		// operate
		Transport.transfer(message, mockHttpTransmitter);

		// verify
		EasyMock.verify(mockHttpTransmitter);
	}

	@Test
	public void insecureChannelFails() throws Exception {
		// setup
		IdentityDataMessage identityDataMessage = new IdentityDataMessage();

		HttpTransmitter mockHttpTransmitter = EasyMock
				.createMock(HttpTransmitter.class);

		// stubs
		EasyMock.expect(mockHttpTransmitter.isSecure()).andReturn(false);

		// prepare
		EasyMock.replay(mockHttpTransmitter);

		// operate & verify
		try {
			Transport.transfer(identityDataMessage, mockHttpTransmitter);
			fail();
		} catch (SecurityException e) {
			// expected
			EasyMock.verify(mockHttpTransmitter);
		}
	}

	@Test
	public void inputValidationFailure() throws Exception {
		// setup
		IdentityDataMessage identityDataMessage = new IdentityDataMessage();

		HttpTransmitter mockHttpTransmitter = EasyMock
				.createMock(HttpTransmitter.class);

		// stubs
		EasyMock.expect(mockHttpTransmitter.isSecure()).andReturn(true);

		// prepare
		EasyMock.replay(mockHttpTransmitter);

		// operate & verify
		try {
			Transport.transfer(identityDataMessage, mockHttpTransmitter);
			fail();
		} catch (IllegalArgumentException e) {
			// expected
			EasyMock.verify(mockHttpTransmitter);
		}
	}
}
