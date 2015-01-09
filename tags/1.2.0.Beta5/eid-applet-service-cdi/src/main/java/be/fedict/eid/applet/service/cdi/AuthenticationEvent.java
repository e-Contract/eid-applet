/*
 * eID Applet Project.
 * Copyright (C) 2014 e-Contract.be BVBA.
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

public class AuthenticationEvent {

	private final List<X509Certificate> authCertChain;

	private boolean valid;

	private boolean invalid;

	public AuthenticationEvent(List<X509Certificate> authCertChain) {
		this.authCertChain = authCertChain;
	}

	public List<X509Certificate> getAuthenticationCertificateChain() {
		return this.authCertChain;
	}

	public void valid() {
		this.valid = true;
	}

	public void invalid() {
		this.invalid = true;
	}

	public boolean isValid() {
		if (this.invalid) {
			return false;
		}
		return this.valid;
	}
}
