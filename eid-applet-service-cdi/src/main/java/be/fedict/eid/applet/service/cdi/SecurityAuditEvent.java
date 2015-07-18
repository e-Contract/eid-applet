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

public class SecurityAuditEvent {

	public static enum Incident {
		SIGNATURE, TRUST, TRANSPORT, DATA_INTEGRITY
	}

	private final Incident incident;

	private final X509Certificate subject;

	private final byte[] data;

	public SecurityAuditEvent(Incident incident, X509Certificate subject, byte[] data) {
		this.incident = incident;
		this.subject = subject;
		this.data = data;
	}

	public SecurityAuditEvent(Incident incident, X509Certificate subject) {
		this(incident, subject, null);
	}

	public SecurityAuditEvent(Incident incident, byte[] data) {
		this(incident, null, data);
	}

	public Incident getIncident() {
		return this.incident;
	}

	public X509Certificate getSubject() {
		return this.subject;
	}

	public byte[] getData() {
		return this.data;
	}
}