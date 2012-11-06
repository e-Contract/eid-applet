/*
 * eID Applet Project.
 * Copyright (C) 2008-2012 FedICT.
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

package test.be.fedict.eid.applet.model;

import java.security.KeyStore;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;

import javax.ejb.Local;
import javax.ejb.Stateless;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jboss.ejb3.annotation.LocalBinding;

import be.fedict.commons.eid.consumer.jca.ProxyPrivateKey;
import be.fedict.commons.eid.consumer.jca.ProxyProvider;
import be.fedict.eid.applet.service.spi.AuthenticationSignatureContext;
import be.fedict.eid.applet.service.spi.AuthenticationSignatureService;
import be.fedict.eid.applet.service.spi.DigestInfo;

@Stateless
@Local(AuthenticationSignatureService.class)
@LocalBinding(jndiBinding = "test/eid/applet/model/AuthenticationSignatureServiceBean")
public class AuthenticationSignatureServiceBean implements
		AuthenticationSignatureService {

	private static final Log LOG = LogFactory
			.getLog(AuthenticationSignatureServiceBean.class);

	static {
		/*
		 * Quick-and-dirty work-around. We should explicitly handle the
		 * lifecycle of this security provider so we can redeploy the
		 * application multiple times.
		 */
		Security.addProvider(new ProxyProvider());
	}

	public DigestInfo preSign(List<X509Certificate> authnCertificateChain,
			AuthenticationSignatureContext authenticationSignatureContext) {
		LOG.debug("preSign");
		LOG.debug("authn cert chain size: " + authnCertificateChain.size());

		KeyStore proxyKeyStore;
		final ProxyPrivateKey proxyPrivateKey;
		try {
			proxyKeyStore = KeyStore.getInstance("ProxyBeID");
			proxyKeyStore.load(null);
			proxyPrivateKey = (ProxyPrivateKey) proxyKeyStore.getKey(
					"Signature", null);
		} catch (Exception e) {
			throw new RuntimeException("error loading ProxyBeID keystore");
		}

		FutureTask<String> signTask = new FutureTask<String>(
				new Callable<String>() {
					public String call() throws Exception {
						final Signature signature = Signature
								.getInstance("SHA256withRSA");
						signature.initSign(proxyPrivateKey);

						final byte[] toBeSigned = "hello world".getBytes();
						signature.update(toBeSigned);
						final byte[] signatureValue = signature.sign();
						LOG.debug("received signature value");
						return "signature result";
					}

				});
		final ExecutorService executor = Executors.newFixedThreadPool(1);
		executor.execute(signTask);

		authenticationSignatureContext.store("key", proxyPrivateKey);
		authenticationSignatureContext.store("signTask", signTask);

		byte[] digestValue;
		try {
			digestValue = proxyPrivateKey.getDigestInfo().getDigestValue();
		} catch (InterruptedException e) {
			throw new RuntimeException("signature error: " + e.getMessage(), e);
		}
		DigestInfo digestInfo = new DigestInfo(digestValue, "SHA-256",
				"WS-Security message");
		return digestInfo;
	}

	public void postSign(byte[] signatureValue,
			List<X509Certificate> authnCertificateChain,
			AuthenticationSignatureContext authenticationSignatureContext) {
		LOG.debug("postSign: " + (signatureValue != null));

		ProxyPrivateKey proxyPrivateKey = (ProxyPrivateKey) authenticationSignatureContext
				.load("key");
		proxyPrivateKey.setSignatureValue(signatureValue);

		FutureTask<String> signTask = (FutureTask<String>) authenticationSignatureContext
				.load("signTask");
		String signatureResult;
		try {
			signatureResult = signTask.get();
		} catch (Exception e) {
			throw new RuntimeException("sign task error: " + e.getMessage(), e);
		}

		HttpServletRequest httpServletRequest;
		try {
			httpServletRequest = (HttpServletRequest) PolicyContext
					.getContext("javax.servlet.http.HttpServletRequest");
		} catch (PolicyContextException e) {
			throw new RuntimeException("JACC error: " + e.getMessage());
		}

		HttpSession httpSession = httpServletRequest.getSession();
		httpSession.setAttribute("AuthenticationSignatureValue",
				signatureResult);
	}
}
