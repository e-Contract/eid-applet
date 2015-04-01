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

package be.fedict.eid.applet.service.cdi;

import java.security.cert.X509Certificate;
import java.util.List;

public class SignatureDigestEvent {

	private byte[] digestValue;

	private String digestAlgo;

	private String description;

	private boolean logoff;

	private boolean removeCard;

	private final List<X509Certificate> signingCertificateChain;

	public SignatureDigestEvent() {
		super();
		this.signingCertificateChain = null;
	}

	public SignatureDigestEvent(List<X509Certificate> signingCertificateChain) {
		this.signingCertificateChain = signingCertificateChain;
	}

	public void sign(byte[] digestValue, String digestAlgo, String description) {
		this.digestValue = digestValue;
		this.digestAlgo = digestAlgo;
		this.description = description;
	}

	public byte[] getDigestValue() {
		return this.digestValue;
	}

	public String getDigestAlgo() {
		return this.digestAlgo;
	}

	public String getDescription() {
		return this.description;
	}

	public SignatureDigestEvent logoff() {
		this.logoff = true;
		return this;
	}

	public SignatureDigestEvent removeCard() {
		this.removeCard = true;
		return this;
	}

	public boolean isLogoff() {
		return this.logoff;
	}

	public boolean isRemoveCard() {
		return this.removeCard;
	}

	public List<X509Certificate> getSigningCertificateChain() {
		return this.signingCertificateChain;
	}
}
