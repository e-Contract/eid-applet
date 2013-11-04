/*
 * eID Applet Project.
 * Copyright (C) 2012 FedICT.
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

package be.fedict.eid.applet.service.spi;

import java.io.Serializable;

public class PreSignResult implements Serializable {

	private static final long serialVersionUID = 1L;

	private final DigestInfo digestInfo;

	private final boolean logoff;

	public PreSignResult(DigestInfo digestInfo, boolean logoff) {
		this.digestInfo = digestInfo;
		this.logoff = logoff;
	}

	public DigestInfo getDigestInfo() {
		return this.digestInfo;
	}

	public boolean getLogoff() {
		return this.logoff;
	}
}
