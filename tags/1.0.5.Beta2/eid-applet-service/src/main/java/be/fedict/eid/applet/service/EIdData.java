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

package be.fedict.eid.applet.service;

import java.io.Serializable;

/**
 * Top-level eID data container.
 * 
 * @author Frank Cornelis
 * 
 */
public class EIdData implements Serializable {

	private static final long serialVersionUID = 1L;

	public Identity identity;

	public Address address;

	public byte[] photo;

	public String identifier;

	public EIdCertsData certs;

	public static long getSerialVersionUID() {
		return serialVersionUID;
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

	public String getIdentifier() {
		return this.identifier;
	}

	public EIdCertsData getCerts() {
		return this.certs;
	}
}
