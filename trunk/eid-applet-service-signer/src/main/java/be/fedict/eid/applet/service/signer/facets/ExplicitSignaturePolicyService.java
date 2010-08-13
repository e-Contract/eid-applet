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

/**
 * Explicit signature policy service implementation.
 * 
 * @author Frank Cornelis
 * 
 */
public class ExplicitSignaturePolicyService implements SignaturePolicyService {

	private final String signaturePolicyIdentifier;

	private final String signaturePolicyDescription;

	private final String signaturePolicyDownloadUrl;

	private final byte[] signaturePolicyDocument;

	/**
	 * Main constructor.
	 * 
	 * @param signaturePolicyIdentifier
	 *            the identifier URI.
	 * @param signaturePolicyDocument
	 * @param signaturePolicyDescription
	 *            the optional description.
	 * @param signaturePolicyDownloadUrl
	 *            the optional download URL.
	 */
	public ExplicitSignaturePolicyService(String signaturePolicyIdentifier,
			byte[] signaturePolicyDocument, String signaturePolicyDescription,
			String signaturePolicyDownloadUrl) {
		super();
		this.signaturePolicyIdentifier = signaturePolicyIdentifier;
		this.signaturePolicyDocument = signaturePolicyDocument;
		this.signaturePolicyDescription = signaturePolicyDescription;
		this.signaturePolicyDownloadUrl = signaturePolicyDownloadUrl;
	}

	public String getSignaturePolicyDescription() {
		return this.signaturePolicyDescription;
	}

	public byte[] getSignaturePolicyDocument() {
		return this.signaturePolicyDocument;
	}

	public String getSignaturePolicyDownloadUrl() {
		return this.signaturePolicyDownloadUrl;
	}

	public String getSignaturePolicyIdentifier() {
		return this.signaturePolicyIdentifier;
	}
}
