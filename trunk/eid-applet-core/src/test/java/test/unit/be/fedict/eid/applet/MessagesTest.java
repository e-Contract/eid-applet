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

import static org.junit.Assert.assertNotNull;

import java.util.Locale;

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
}
