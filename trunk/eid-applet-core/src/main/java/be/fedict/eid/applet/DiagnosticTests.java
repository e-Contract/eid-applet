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

package be.fedict.eid.applet;

public enum DiagnosticTests {
	JAVA_RUNTIME("Java runtime"), PCSC("PC/SC layer"), CARD_READER(
			"Card reader"), EID_READOUT("eID readout"), EID_CRYPTO("eID crypto"), PKCS11_AVAILABLE(
			"eID Middleware PKCS#11"), PKCS11_RUNTIME("PKCS#11 runtime"), MSCAPI(
			"Windows CSP runtime");

	private final String description;

	private DiagnosticTests(String description) {
		this.description = description;
	}

	public String getDescription() {
		return this.description;
	}
}
