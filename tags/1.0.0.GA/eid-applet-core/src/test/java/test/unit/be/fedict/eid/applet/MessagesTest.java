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

package test.unit.be.fedict.eid.applet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;
import java.util.Locale;
import java.util.Properties;
import java.util.ResourceBundle;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import be.fedict.eid.applet.Messages;
import be.fedict.eid.applet.Messages.MESSAGE_ID;

public class MessagesTest {

	private static final Log LOG = LogFactory.getLog(MessagesTest.class);

	@Test
	public void getMessage() throws Exception {
		Locale locale = Locale.getDefault();
		Messages messages = new Messages(locale);
		assertNotNull(messages.getMessage(MESSAGE_ID.INSERT_CARD_QUESTION));
		LOG.debug("done msg: " + messages.getMessage(MESSAGE_ID.DONE));
	}

	@Test
	public void testFrenchMessages() throws Exception {
		Locale locale = Locale.FRENCH;
		Messages messages = new Messages(locale);
		String message = messages.getMessage(Messages.MESSAGE_ID.GENERIC_ERROR);
		LOG.debug("message: " + message);
	}

	@Test
	public void allStringsAvailable() throws Exception {
		allStringsAvailable("");
		allStringsAvailable("nl");
		allStringsAvailable("fr");
	}

	private void allStringsAvailable(String language) throws Exception {
		if (false == language.isEmpty()) {
			language = "_" + language;
		}
		InputStream messagesInputStream = MessagesTest.class
				.getResourceAsStream("/be/fedict/eid/applet/Messages"
						+ language + ".properties");
		Properties properties = new Properties();
		properties.load(messagesInputStream);
		for (MESSAGE_ID messageId : MESSAGE_ID.values()) {
			assertTrue("missing message \"" + messageId.getId()
					+ "\" for language \"" + language + "\"", properties
					.containsKey(messageId.getId()));
		}
	}

	@Test
	public void testEncoding() throws Exception {
		ResourceBundle resourceBundle = ResourceBundle.getBundle("test");
		String testMessage = resourceBundle.getString("test");
		LOG.debug("test message: " + testMessage);
		assertEquals("é", testMessage);
	}
}
