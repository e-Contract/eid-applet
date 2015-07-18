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

import be.fedict.eid.applet.shared.ErrorCode;

public class SignatureEvent {

	private final byte[] signatureValue;

	private final List<X509Certificate> certificateChain;

	private ErrorCode errorCode;

	public SignatureEvent(byte[] signatureValue, List<X509Certificate> certificateChain) {
		this.signatureValue = signatureValue;
		this.certificateChain = certificateChain;
	}

	public byte[] getSignatureValue() {
		return this.signatureValue;
	}

	public List<X509Certificate> getCertificateChain() {
		return this.certificateChain;
	}

	public void setError(ErrorCode errorCode) {
		if (null != this.errorCode) {
			return;
		}
		this.errorCode = errorCode;
	}

	public ErrorCode getError() {
		return this.errorCode;
	}
}
