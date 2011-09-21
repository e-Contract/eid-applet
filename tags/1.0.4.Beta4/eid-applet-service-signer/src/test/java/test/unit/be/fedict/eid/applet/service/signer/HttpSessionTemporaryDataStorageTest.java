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

package test.unit.be.fedict.eid.applet.service.signer;

import static org.junit.Assert.assertArrayEquals;

import java.io.InputStream;
import java.io.OutputStream;

import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.security.jacc.PolicyContextHandler;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.io.IOUtils;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.easymock.IAnswer;
import org.junit.Test;

import be.fedict.eid.applet.service.signer.HttpSessionTemporaryDataStorage;

public class HttpSessionTemporaryDataStorageTest {

	@Test
	public void testStorage() throws Exception {
		// setup
		HttpSessionTemporaryDataStorage testedInstance = new HttpSessionTemporaryDataStorage();
		byte[] data = "hello world".getBytes();

		HttpServletRequest mockHttpServletRequest = EasyMock
				.createMock(HttpServletRequest.class);
		PolicyContextHandler policyContextHandler = new HttpServletRequestPolicyContextHandler(
				mockHttpServletRequest);
		PolicyContext.registerHandler(
				HttpServletRequestPolicyContextHandler.KEY,
				policyContextHandler, false);

		HttpSession mockHttpSession = EasyMock.createMock(HttpSession.class);
		EasyMock.expect(mockHttpServletRequest.getSession()).andStubReturn(
				mockHttpSession);
		final Capture<OutputStream> tempOutputStreamCapture = new Capture<OutputStream>();
		mockHttpSession
				.setAttribute(
						EasyMock
								.eq(HttpSessionTemporaryDataStorage.TEMP_OUTPUT_STREAM_ATTRIBUTE),
						EasyMock.capture(tempOutputStreamCapture));
		EasyMock
				.expect(
						mockHttpSession
								.getAttribute(HttpSessionTemporaryDataStorage.TEMP_OUTPUT_STREAM_ATTRIBUTE))
				.andAnswer(new IAnswer<OutputStream>() {
					public OutputStream answer() throws Throwable {
						return tempOutputStreamCapture.getValue();
					}
				});

		// prepare
		EasyMock.replay(mockHttpServletRequest, mockHttpSession);

		// operate
		OutputStream outputStream = testedInstance.getTempOutputStream();
		IOUtils.write(data, outputStream);

		InputStream inputStream = testedInstance.getTempInputStream();
		byte[] resultData = IOUtils.toByteArray(inputStream);

		// verify
		EasyMock.verify(mockHttpServletRequest, mockHttpSession);
		assertArrayEquals(data, resultData);
	}

	public static class HttpServletRequestPolicyContextHandler implements
			PolicyContextHandler {

		public static final String KEY = "javax.servlet.http.HttpServletRequest";

		private final HttpServletRequest httpServletRequest;

		private HttpServletRequestPolicyContextHandler(
				HttpServletRequest httpServletRequest) {
			this.httpServletRequest = httpServletRequest;
		}

		public Object getContext(String key, Object data)
				throws PolicyContextException {
			if (false == KEY.equals(key)) {
				return null;
			}
			return this.httpServletRequest;
		}

		public String[] getKeys() throws PolicyContextException {
			return new String[] { KEY };
		}

		public boolean supports(String key) throws PolicyContextException {
			return KEY.equals(key);
		}
	}
}
