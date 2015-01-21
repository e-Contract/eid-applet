/*
 * eID Applet Project.
 * Copyright (C) 2008-2009 FedICT.
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

package be.fedict.eid.applet.shared;

import java.util.List;

import be.fedict.eid.applet.shared.annotation.HttpBody;
import be.fedict.eid.applet.shared.annotation.HttpHeader;
import be.fedict.eid.applet.shared.annotation.MessageDiscriminator;
import be.fedict.eid.applet.shared.annotation.NotNull;
import be.fedict.eid.applet.shared.annotation.ProtocolStateAllowed;
import be.fedict.eid.applet.shared.annotation.ResponsesAllowed;
import be.fedict.eid.applet.shared.protocol.ProtocolState;

/**
 * Client environment message transfer object.
 * 
 * @author Frank Cornelis
 * 
 */
@ProtocolStateAllowed(ProtocolState.ENV_CHECK)
@ResponsesAllowed({ IdentificationRequestMessage.class,
		InsecureClientMessage.class, AuthenticationRequestMessage.class,
		AdministrationMessage.class, SignRequestMessage.class,
		FilesDigestRequestMessage.class, SignCertificatesRequestMessage.class,
		FinishedMessage.class })
public class ClientEnvironmentMessage extends AbstractProtocolMessage {
	@HttpHeader(TYPE_HTTP_HEADER)
	@MessageDiscriminator
	public static final String TYPE = ClientEnvironmentMessage.class
			.getSimpleName();

	@HttpHeader(HTTP_HEADER_PREFIX + "JavaVersion")
	@NotNull
	public String javaVersion;

	@HttpHeader(HTTP_HEADER_PREFIX + "JavaVendor")
	@NotNull
	public String javaVendor;

	@HttpHeader(HTTP_HEADER_PREFIX + "OSName")
	@NotNull
	public String osName;

	@HttpHeader(HTTP_HEADER_PREFIX + "OSArch")
	@NotNull
	public String osArch;

	@HttpHeader(HTTP_HEADER_PREFIX + "OSVersion")
	@NotNull
	public String osVersion;

	@HttpHeader(HTTP_HEADER_PREFIX + "NavigatorUserAgent")
	public String navigatorUserAgent;

	@HttpHeader(HTTP_HEADER_PREFIX + "NavigatorAppName")
	public String navigatorAppName;

	@HttpHeader(HTTP_HEADER_PREFIX + "NavigatorAppVersion")
	public String navigatorAppVersion;

	@HttpBody
	@NotNull
	public List<String> readerList;
}
