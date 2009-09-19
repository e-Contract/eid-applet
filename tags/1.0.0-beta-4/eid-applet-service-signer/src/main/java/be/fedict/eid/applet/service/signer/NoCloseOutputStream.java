/*
 * eID Applet Project.
 * Copyright (C) 2009 FedICT.
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
 * Output Stream proxy that doesn't close the underlying stream.
 * 
 * @author fcorneli
 * 
 */
public class NoCloseOutputStream extends ProxyOutputStream {

	private static final Log LOG = LogFactory.getLog(NoCloseOutputStream.class);

	/**
	 * Main constructor.
	 * 
	 * @param proxy
	 */
	public NoCloseOutputStream(OutputStream proxy) {
		super(proxy);
	}

	@Override
	public void close() throws IOException {
		LOG.debug("close");
		// empty
	}
}