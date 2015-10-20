/*
 * eID Applet Project.
 * Copyright (C) 2014-2015 e-Contract.be BVBA.
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

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;

public class IdentityEvent {

	private final Identity identity;

	private final Address address;

	private final byte[] photo;
	
	private final X509Certificate authenticationCertificate;

	public IdentityEvent(Identity identity, Address address, byte[] photo, X509Certificate authenticationCertificate) {
		this.identity = identity;
		this.address = address;
		this.photo = photo;
		this.authenticationCertificate = authenticationCertificate;
	}

	public Identity getIdentity() {
		return this.identity;
	}

	public Address getAddress() {
		return this.address;
	}

	public byte[] getPhoto() {
		return this.photo;
	}

	public X509Certificate getAuthenticationCertificate() {
		return this.authenticationCertificate;
	}	
}
