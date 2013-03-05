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

package be.fedict.eid.applet.shared;

import be.fedict.eid.applet.shared.protocol.SemanticValidator;
import be.fedict.eid.applet.shared.protocol.SemanticValidatorException;

/**
 * Semantic validator implementation of the IdentityDataMessage.
 * 
 * @author Frank Cornelis
 * 
 */
public class IdentityDataMessageSemanticValidator implements
		SemanticValidator<IdentityDataMessage> {

	public void validate(IdentityDataMessage object)
			throws SemanticValidatorException {
		int expectedSize = object.identityFileSize;
		if (null != object.addressFileSize) {
			expectedSize += object.addressFileSize;
		}
		if (null != object.photoFileSize) {
			expectedSize += object.photoFileSize;
		}
		if (null != object.identitySignatureFileSize) {
			expectedSize += object.identitySignatureFileSize;
		}
		if (null != object.addressSignatureFileSize) {
			expectedSize += object.addressSignatureFileSize;
		}
		if (null != object.authnCertFileSize) {
			expectedSize += object.authnCertFileSize;
		}
		if (null != object.signCertFileSize) {
			expectedSize += object.signCertFileSize;
		}
		if (null != object.caCertFileSize) {
			expectedSize += object.caCertFileSize;
		}
		if (null != object.rrnCertFileSize) {
			expectedSize += object.rrnCertFileSize;
		}
		if (null != object.rootCertFileSize) {
			expectedSize += object.rootCertFileSize;
		}
		if (expectedSize != object.body.length) {
			throw new SemanticValidatorException("body size incorrect");
		}
	}
}
