/*
 * eID Applet Project.
 * Copyright (C) 2010-2011 FedICT.
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

package be.fedict.eid.applet.service.signer;

import java.io.IOException;
import java.io.OutputStream;

import org.apache.commons.io.output.ProxyOutputStream;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * An output stream proxy implementation that allows us to run something when
 * the stream has been closed. Useful to perform resource cleanup tasks.
 * 
 * @author Frank Cornelis
 * 
 */
public class CloseActionOutputStream extends ProxyOutputStream {

	private static final Log LOG = LogFactory
			.getLog(CloseActionOutputStream.class);

	private final Runnable closeAction;

	public CloseActionOutputStream(OutputStream proxy, Runnable closeAction) {
		super(proxy);
		if (null == closeAction) {
			throw new IllegalArgumentException("null closeAction");
		}
		this.closeAction = closeAction;
	}

	@Override
	public void close() throws IOException {
		super.close();
		LOG.debug("running close action");
		this.closeAction.run();
	}
}
