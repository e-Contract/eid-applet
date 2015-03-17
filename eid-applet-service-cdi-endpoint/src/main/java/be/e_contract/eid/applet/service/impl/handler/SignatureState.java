/*
 * eID Applet Project.
 * Copyright (C) 2015 e-Contract.be BVBA.
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

package be.e_contract.eid.applet.service.impl.handler;

import java.io.Serializable;

import javax.enterprise.context.SessionScoped;

@SessionScoped
public class SignatureState implements Serializable {

	private static final long serialVersionUID = 1L;

	private byte[] digestValue;

	private String digestAlgo;

	public byte[] getDigestValue() {
		return this.digestValue;
	}

	public void setDigestValue(byte[] digestValue) {
		this.digestValue = digestValue;
	}

	public String getDigestAlgo() {
		return this.digestAlgo;
	}

	public void setDigestAlgo(String digestAlgo) {
		this.digestAlgo = digestAlgo;
	}
}
