/*
 * eID Applet Project.
 * Copyright (C) 2009 FedICT.
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

package test.unit.be.fedict.eid.applet.service;

import java.security.cert.X509Certificate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.spi.AuditService;

public class AuditTestService implements AuditService {

	private static final Log LOG = LogFactory.getLog(AuditTestService.class);

	private static String auditUserId;

	private static String auditRemoteAddress;

	private static X509Certificate auditClientCertificate;

	private static String auditSigningUserId;

	public static void reset() {
		AuditTestService.auditUserId = null;
		AuditTestService.auditRemoteAddress = null;
		AuditTestService.auditClientCertificate = null;
		AuditTestService.auditIntegrityRemoteAddress = null;
		AuditTestService.auditSignatureRemoteAddress = null;
		AuditTestService.auditSignatureClientCertificate = null;
		AuditTestService.auditSigningUserId = null;
	}

	public static String getAuditUserId() {
		return AuditTestService.auditUserId;
	}

	public static String getAuditRemoteAddress() {
		return AuditTestService.auditRemoteAddress;
	}

	public static X509Certificate getAuditClientCertificate() {
		return AuditTestService.auditClientCertificate;
	}

	public void authenticated(String userId) {
		LOG.debug("authenticated: " + userId);
		AuditTestService.auditUserId = userId;
	}

	public void authenticationError(String remoteAddress,
			X509Certificate clientCertificate) {
		LOG.debug("authentication error: " + remoteAddress);
		AuditTestService.auditRemoteAddress = remoteAddress;
		AuditTestService.auditClientCertificate = clientCertificate;
	}

	private static String auditIntegrityRemoteAddress;

	public static String getAuditIntegrityRemoteAddress() {
		return AuditTestService.auditIntegrityRemoteAddress;
	}

	public void identityIntegrityError(String remoteAddress) {
		AuditTestService.auditIntegrityRemoteAddress = remoteAddress;
	}

	private static String auditSignatureRemoteAddress;

	private static X509Certificate auditSignatureClientCertificate;

	public static String getAuditSignatureRemoteAddress() {
		return AuditTestService.auditSignatureRemoteAddress;
	}

	public static X509Certificate getAuditSignatureClientCertificate() {
		return AuditTestService.auditSignatureClientCertificate;
	}

	public void signatureError(String remoteAddress,
			X509Certificate clientCertificate) {
		AuditTestService.auditSignatureRemoteAddress = remoteAddress;
		AuditTestService.auditSignatureClientCertificate = clientCertificate;
	}

	public void signed(String userId) {
		AuditTestService.auditSigningUserId = userId;
	}

	public static String getAuditSigningUserId() {
		return AuditTestService.auditSigningUserId;
	}

	public void identified(String userId) {
		// empty
	}
}