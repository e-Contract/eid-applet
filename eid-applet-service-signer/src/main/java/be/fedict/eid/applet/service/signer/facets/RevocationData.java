/*
 * eID Applet Project.
 * Copyright (C) 2010 FedICT.
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

package be.fedict.eid.applet.service.signer.facets;

import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.LinkedList;
import java.util.List;

/**
 * Container class for PKI revocation data.
 * 
 * @author Frank Cornelis
 * 
 */
public class RevocationData {

	private final List<byte[]> crls;

	private final List<byte[]> ocsps;

	public RevocationData() {
		this.crls = new LinkedList<byte[]>();
		this.ocsps = new LinkedList<byte[]>();
	}

	public void addCRL(byte[] encodedCrl) {
		this.crls.add(encodedCrl);
	}

	public void addCRL(X509CRL crl) {
		byte[] encodedCrl;
		try {
			encodedCrl = crl.getEncoded();
		} catch (CRLException e) {
			throw new IllegalArgumentException("CRL coding error: "
					+ e.getMessage(), e);
		}
		addCRL(encodedCrl);
	}

	public void addOCSP(byte[] encodedOcsp) {
		this.ocsps.add(encodedOcsp);
	}

	public List<byte[]> getCRLs() {
		return this.crls;
	}

	public List<byte[]> getOCSPs() {
		return this.ocsps;
	}

	public boolean hasOCSPs() {
		return false == this.ocsps.isEmpty();
	}

	public boolean hasCRLs() {
		return false == this.crls.isEmpty();
	}

	public boolean hasRevocationDataEntries() {
		return hasOCSPs() || hasCRLs();
	}
}
