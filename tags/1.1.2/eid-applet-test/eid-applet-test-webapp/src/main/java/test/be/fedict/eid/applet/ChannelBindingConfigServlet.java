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

package test.be.fedict.eid.applet;

import java.io.IOException;
import java.io.StringReader;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;

public class ChannelBindingConfigServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	@Override
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		Provider provider = null;
		if (null == Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)) {
			provider = new BouncyCastleProvider();
			Security.addProvider(provider);
		}
		String serverCertificatePem = request.getParameter("serverCertificate");
		PEMReader pemReader = new PEMReader(new StringReader(
				serverCertificatePem));
		Object object = pemReader.readObject();
		pemReader.close();
		if (object instanceof X509Certificate) {
			X509Certificate serverCertificate = (X509Certificate) object;
			HttpSession httpSession = request.getSession();
			httpSession
					.setAttribute(
							"test.be.fedict.eid.applet.model.ChannelBindingServiceBean.serverCertificate",
							serverCertificate);
		}
		response.sendRedirect("channel-binding.jsp");
		if (null != provider) {
			Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
		}
	}
}
