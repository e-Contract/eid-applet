/*
 * eID Applet Project.
 * Copyright (C) 2008-2009 FedICT.
 * Copyright (C) 2009 Frank Cornelis.
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

import java.awt.Component;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.CookieHandler;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.DigestInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Observable;
import java.util.Observer;

import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

import sun.security.pkcs11.wrapper.PKCS11Exception;
import be.fedict.eid.applet.Messages.MESSAGE_ID;
import be.fedict.eid.applet.io.AppletSSLSocketFactory;
import be.fedict.eid.applet.io.HttpURLConnectionHttpReceiver;
import be.fedict.eid.applet.io.HttpURLConnectionHttpTransmitter;
import be.fedict.eid.applet.io.LocalAppletProtocolContext;
import be.fedict.eid.applet.sc.DiagnosticCallbackHandler;
import be.fedict.eid.applet.sc.PKCS11NotFoundException;
import be.fedict.eid.applet.sc.PcscEid;
import be.fedict.eid.applet.sc.PcscEidSpi;
import be.fedict.eid.applet.sc.Pkcs11Eid;
import be.fedict.eid.applet.sc.Task;
import be.fedict.eid.applet.sc.TaskRunner;
import be.fedict.eid.applet.shared.AdministrationMessage;
import be.fedict.eid.applet.shared.AppletProtocolMessageCatalog;
import be.fedict.eid.applet.shared.AuthenticationContract;
import be.fedict.eid.applet.shared.AuthenticationDataMessage;
import be.fedict.eid.applet.shared.AuthenticationRequestMessage;
import be.fedict.eid.applet.shared.CheckClientMessage;
import be.fedict.eid.applet.shared.ClientEnvironmentMessage;
import be.fedict.eid.applet.shared.ContinueInsecureMessage;
import be.fedict.eid.applet.shared.DiagnosticMessage;
import be.fedict.eid.applet.shared.FileDigestsDataMessage;
import be.fedict.eid.applet.shared.FilesDigestRequestMessage;
import be.fedict.eid.applet.shared.FinishedMessage;
import be.fedict.eid.applet.shared.HelloMessage;
import be.fedict.eid.applet.shared.IdentificationRequestMessage;
import be.fedict.eid.applet.shared.IdentityDataMessage;
import be.fedict.eid.applet.shared.InsecureClientMessage;
import be.fedict.eid.applet.shared.KioskMessage;
import be.fedict.eid.applet.shared.SignCertificatesDataMessage;
import be.fedict.eid.applet.shared.SignCertificatesRequestMessage;
import be.fedict.eid.applet.shared.SignRequestMessage;
import be.fedict.eid.applet.shared.SignatureDataMessage;
import be.fedict.eid.applet.shared.annotation.ResponsesAllowed;
import be.fedict.eid.applet.shared.protocol.ProtocolContext;
import be.fedict.eid.applet.shared.protocol.ProtocolStateMachine;
import be.fedict.eid.applet.shared.protocol.Transport;
import be.fedict.eid.applet.shared.protocol.Unmarshaller;

/**
 * Controller component. Contains the eID logic. Interacts with {@link View} and
 * {@link Runtime} for outside world communication.
 * 
 * @author Frank Cornelis
 * 
 */
public class Controller {

	private final View view;

	private final Runtime runtime;

	private final Messages messages;

	/**
	 * Will only be set if PC/SC Java 6 is available.
	 */
	private final PcscEidSpi pcscEidSpi;

	private final Pkcs11Eid pkcs11Eid;

	private final ProtocolStateMachine protocolStateMachine;

	@SuppressWarnings("unchecked")
	public Controller(View view, Runtime runtime, Messages messages) {
		this.view = view;
		this.runtime = runtime;
		this.messages = messages;
		if (false == System.getProperty("java.version").startsWith("1.5")) {
			/*
			 * Java 1.6 and later. Loading the PcscEid class via reflection
			 * avoids a hard reference to Java 1.6 specific code. This is
			 * required in order to be able to let a Java 1.5 runtime load this
			 * Controller class without exploding on unsupported 1.6 types.
			 */
			try {
				Class<? extends PcscEidSpi> pcscEidClass = (Class<? extends PcscEidSpi>) Class
						.forName("be.fedict.eid.applet.sc.PcscEid");
				Constructor<? extends PcscEidSpi> pcscEidConstructor = pcscEidClass
						.getConstructor(View.class, Messages.class);
				this.pcscEidSpi = pcscEidConstructor.newInstance(this.view,
						this.messages);
			} catch (Exception e) {
				String msg = "error loading PC/SC eID component: "
						+ e.getMessage();
				this.view.addDetailMessage(msg);
				throw new RuntimeException(msg);
			}
			this.pcscEidSpi.addObserver(new PcscEidObserver());
		} else {
			/*
			 * No PC/SC Java 6 available.
			 */
			this.pcscEidSpi = null;
		}
		this.pkcs11Eid = new Pkcs11Eid(this.view, this.messages);
		ProtocolContext protocolContext = new LocalAppletProtocolContext(
				this.view);
		this.protocolStateMachine = new ProtocolStateMachine(protocolContext);
	}

	private <T> T sendMessage(Object message, Class<T> responseClass)
			throws MalformedURLException, IOException {
		Object responseObject = sendMessage(message);
		if (false == responseClass.equals(responseObject.getClass())) {
			throw new RuntimeException("response message not of type: "
					+ responseClass.getName());
		}
		@SuppressWarnings("unchecked")
		T response = (T) responseObject;
		return response;
	}

	private Object sendMessage(Object message) throws MalformedURLException,
			IOException {
		addDetailMessage("sending message: "
				+ message.getClass().getSimpleName());
		Class<?> messageClass = message.getClass();
		ResponsesAllowed responsesAllowedAnnotation = messageClass
				.getAnnotation(ResponsesAllowed.class);
		if (null == responsesAllowedAnnotation) {
			throw new RuntimeException(
					"message should have a @ResponsesAllowed constraint");
		}

		this.protocolStateMachine.checkRequestMessage(message);

		HttpURLConnection connection = getServerConnection();
		HttpURLConnectionHttpTransmitter httpTransmitter = new HttpURLConnectionHttpTransmitter(
				connection);
		Transport.transfer(message, httpTransmitter);
		int responseCode = connection.getResponseCode();
		if (HttpURLConnection.HTTP_OK != responseCode) {
			String msg;
			if (HttpURLConnection.HTTP_NOT_FOUND == responseCode) {
				msg = "HTTP NOT FOUND! eID Applet Service not running?";
			} else {
				msg = Integer.toString(responseCode);
			}
			this.view.addDetailMessage("HTTP response code: " + msg);
			printHttpResponseContent(connection);
			throw new IOException(
					"error sending message to service. HTTP status code: "
							+ msg);
		}
		Unmarshaller unmarshaller = new Unmarshaller(
				new AppletProtocolMessageCatalog());
		HttpURLConnectionHttpReceiver httpReceiver = new HttpURLConnectionHttpReceiver(
				connection);
		Object responseObject = unmarshaller.receive(httpReceiver);

		Class<?>[] responsesAllowed = responsesAllowedAnnotation.value();
		if (false == isOfClass(responseObject, responsesAllowed)) {
			throw new RuntimeException("response not of correct type: "
					+ responseObject.getClass());
		}
		addDetailMessage("response message: "
				+ responseObject.getClass().getSimpleName());

		this.protocolStateMachine.checkResponseMessage(responseObject);

		return responseObject;
	}

	private void printHttpResponseContent(HttpURLConnection connection) {
		InputStream errorStream = connection.getErrorStream();
		if (null == errorStream) {
			return;
		}
		BufferedReader reader = new BufferedReader(new InputStreamReader(
				errorStream));
		String line;
		try {
			while (null != (line = reader.readLine())) {
				this.view.addDetailMessage(line);
			}
		} catch (IOException e) {
			this.view.addDetailMessage("I/O error: " + e.getMessage());
		}
	}

	private boolean isOfClass(Object object, Class<?>[] classes) {
		for (Class<?> clazz : classes) {
			if (clazz.equals(object.getClass())) {
				return true;
			}
		}
		return false;
	}

	public Object run() {
		printEnvironment();

		try {
			Applet applet = this.runtime.getApplet();
			String language = applet.getParameter(Applet.LANGUAGE_PARAM);
			HelloMessage helloMessage = new HelloMessage(language);
			Object resultMessage = sendMessage(helloMessage);
			if (resultMessage instanceof CheckClientMessage) {
				addDetailMessage("Need to check the client secure environment...");
				ClientEnvironmentMessage clientEnvMessage = new ClientEnvironmentMessage();
				clientEnvMessage.javaVersion = System
						.getProperty("java.version");
				clientEnvMessage.javaVendor = System.getProperty("java.vendor");
				clientEnvMessage.osName = System.getProperty("os.name");
				clientEnvMessage.osArch = System.getProperty("os.arch");
				clientEnvMessage.osVersion = System.getProperty("os.version");
				if (null != this.pcscEidSpi) {
					/*
					 * First we try it via PC/SC Java 6.
					 */
					clientEnvMessage.readerList = this.pcscEidSpi
							.getReaderList();
				} else {
					/*
					 * Get the reader list via the PKCS#11 library.
					 */
					clientEnvMessage.readerList = this.pkcs11Eid
							.getReaderList();
				}
				clientEnvMessage.navigatorAppName = this.runtime
						.getParameter("NavigatorAppName");
				clientEnvMessage.navigatorAppVersion = this.runtime
						.getParameter("NavigatorAppVersion");
				clientEnvMessage.navigatorUserAgent = this.runtime
						.getParameter("NavigatorUserAgent");
				resultMessage = sendMessage(clientEnvMessage);
				if (resultMessage instanceof InsecureClientMessage) {
					InsecureClientMessage insecureClientMessage = (InsecureClientMessage) resultMessage;
					if (insecureClientMessage.warnOnly) {
						int result = JOptionPane
								.showConfirmDialog(
										this.view.getParentComponent(),
										"Your system has been marked as insecure client environment.\n"
												+ "Do you want to continue the eID operation?",
										"Insecure Client Environment",
										JOptionPane.OK_CANCEL_OPTION,
										JOptionPane.WARNING_MESSAGE);
						if (JOptionPane.OK_OPTION != result) {
							setStatusMessage(Status.ERROR,
									MESSAGE_ID.SECURITY_ERROR);
							addDetailMessage("insecure client environment");
							return null;
						}
						resultMessage = sendMessage(new ContinueInsecureMessage());
					} else {
						JOptionPane
								.showMessageDialog(
										this.view.getParentComponent(),
										"Your system has been marked as insecure client environment.",
										"Insecure Client Environment",
										JOptionPane.ERROR_MESSAGE);
						setStatusMessage(Status.ERROR,
								MESSAGE_ID.SECURITY_ERROR);
						addDetailMessage("received an insecure client environment message");
						return null;
					}
				}
			}
			if (resultMessage instanceof DiagnosticMessage) {
				diagnosticMode();
			}
			if (resultMessage instanceof KioskMessage) {
				kioskMode();
			}
			if (resultMessage instanceof AdministrationMessage) {
				AdministrationMessage administrationMessage = (AdministrationMessage) resultMessage;
				boolean changePin = administrationMessage.changePin;
				boolean unblockPin = administrationMessage.unblockPin;
				boolean removeCard = administrationMessage.removeCard;
				boolean logoff = administrationMessage.logoff;
				boolean requireSecureReader = administrationMessage.requireSecureReader;
				addDetailMessage("change pin: " + changePin);
				addDetailMessage("unblock pin: " + unblockPin);
				addDetailMessage("remove card: " + removeCard);
				addDetailMessage("logoff: " + logoff);
				addDetailMessage("require secure reader: "
						+ requireSecureReader);
				administration(unblockPin, changePin, logoff, removeCard,
						requireSecureReader);
			}
			if (resultMessage instanceof FilesDigestRequestMessage) {
				FilesDigestRequestMessage filesDigestRequestMessage = (FilesDigestRequestMessage) resultMessage;
				resultMessage = performFilesDigestOperation(filesDigestRequestMessage.digestAlgo);
			}
			if (resultMessage instanceof SignCertificatesRequestMessage) {
				SignCertificatesDataMessage signCertificatesDataMessage = performSignCertificatesOperation();
				resultMessage = sendMessage(signCertificatesDataMessage);
			}
			if (resultMessage instanceof SignRequestMessage) {
				SignRequestMessage signRequestMessage = (SignRequestMessage) resultMessage;
				performEidSignOperation(signRequestMessage);
			}
			if (resultMessage instanceof AuthenticationRequestMessage) {
				AuthenticationRequestMessage authnRequest = (AuthenticationRequestMessage) resultMessage;
				resultMessage = performEidAuthnOperation(authnRequest);
			}
			if (resultMessage instanceof IdentificationRequestMessage) {
				IdentificationRequestMessage identificationRequestMessage = (IdentificationRequestMessage) resultMessage;
				addDetailMessage("include address: "
						+ identificationRequestMessage.includeAddress);
				addDetailMessage("include photo: "
						+ identificationRequestMessage.includePhoto);
				addDetailMessage("include integrity data: "
						+ identificationRequestMessage.includeIntegrityData);
				addDetailMessage("include certificates: "
						+ identificationRequestMessage.includeCertificates);
				addDetailMessage("remove card: "
						+ identificationRequestMessage.removeCard);
				addDetailMessage("identity data usage: "
						+ identificationRequestMessage.identityDataUsage);

				performEidIdentificationOperation(
						identificationRequestMessage.includeAddress,
						identificationRequestMessage.includePhoto,
						identificationRequestMessage.includeIntegrityData,
						identificationRequestMessage.includeCertificates,
						identificationRequestMessage.removeCard,
						identificationRequestMessage.identityDataUsage);
			}
			if (resultMessage instanceof FinishedMessage) {
				FinishedMessage finishedMessage = (FinishedMessage) resultMessage;
				if (null != finishedMessage.errorCode) {
					switch (finishedMessage.errorCode) {
					case CERTIFICATE:
						setStatusMessage(Status.ERROR,
								MESSAGE_ID.SECURITY_ERROR);
						return null;
					case CERTIFICATE_EXPIRED:
						setStatusMessage(Status.ERROR,
								MESSAGE_ID.CERTIFICATE_EXPIRED_ERROR);
						return null;
					case CERTIFICATE_REVOKED:
						setStatusMessage(Status.ERROR,
								MESSAGE_ID.CERTIFICATE_REVOKED_ERROR);
						return null;
					default:
					}
					setStatusMessage(Status.ERROR, MESSAGE_ID.GENERIC_ERROR);
					addDetailMessage("error code @ finish: "
							+ finishedMessage.errorCode);
					return null;
				}
			}
		} catch (PKCS11NotFoundException e) {
			setStatusMessage(Status.ERROR, MESSAGE_ID.NO_MIDDLEWARE_ERROR);
			addDetailMessage("error: no eID Middleware PKCS#11 library found");
			return null;
		} catch (SecurityException e) {
			setStatusMessage(Status.ERROR, MESSAGE_ID.SECURITY_ERROR);
			addDetailMessage("error: " + e.getMessage());
			return null;
		} catch (Throwable e) {
			addDetailMessage("error: " + e.getMessage());
			addDetailMessage("error type: " + e.getClass().getName());
			StackTraceElement[] stackTrace = e.getStackTrace();
			for (StackTraceElement stackTraceElement : stackTrace) {
				addDetailMessage("at " + stackTraceElement.getClassName() + "."
						+ stackTraceElement.getMethodName() + ":"
						+ stackTraceElement.getLineNumber());
			}
			Throwable cause = e.getCause();
			if (null != cause) {
				addDetailMessage("Caused by: " + cause.getClass().getName()
						+ ": " + cause.getMessage());
				stackTrace = cause.getStackTrace();
				for (StackTraceElement stackTraceElement : stackTrace) {
					addDetailMessage("at " + stackTraceElement.getClassName()
							+ "." + stackTraceElement.getMethodName() + ":"
							+ stackTraceElement.getLineNumber());
				}
				/*
				 * Next is specific for the OpenSC PKCS#11 library.
				 */
				if (FailedLoginException.class == cause.getClass()) {
					setStatusMessage(Status.ERROR, MESSAGE_ID.PIN_INCORRECT);
					return null;
				}
				if (LoginException.class == cause.getClass()) {
					if (null == cause.getMessage()) {
						/*
						 * This seems to be the case for OpenSC.
						 */
						setStatusMessage(Status.ERROR, MESSAGE_ID.PIN_BLOCKED);
						return null;
					}
					setStatusMessage(Status.ERROR, MESSAGE_ID.SECURITY_ERROR);
					return null;
				}
			}
			/*
			 * We don't refer to javax.smartcardio directly since this code also
			 * need to work an a Java 5 runtime.
			 */
			if ("javax.smartcardio.CardException"
					.equals(e.getClass().getName())) {
				setStatusMessage(Status.ERROR, MESSAGE_ID.CARD_ERROR);
				addDetailMessage("card error: " + e.getMessage());
				return null;
			}
			setStatusMessage(Status.ERROR, MESSAGE_ID.GENERIC_ERROR);
			return null;
		}

		setStatusMessage(Status.NORMAL, MESSAGE_ID.DONE);
		this.runtime.gotoTargetPage();
		return null;
	}

	private void diagnosticMode() {
		addDetailMessage("diagnostic mode...");
		osDiagnosticTest();
		jvmDiagnosticTest();
		browserDiagnosticTest();

		ControllerDiagnosticCallbackHandler callbackHandler = new ControllerDiagnosticCallbackHandler();
		X509Certificate authnCertificate = this.pcscEidSpi
				.diagnosticTests(callbackHandler);
		this.pcscEidSpi.close();

		this.pkcs11Eid.diagnosticTests(callbackHandler);
		try {
			this.pkcs11Eid.close();
		} catch (Exception e) {
			addDetailMessage("error closing PKCS#11: " + e.getMessage());
		}

		mscapiDiagnosticTest(authnCertificate);

		this.view.resetProgress(1);
	}

	private void jvmDiagnosticTest() {
		String javaVersion = System.getProperty("java.version");
		String javaVendor = System.getProperty("java.vendor");
		String javaRuntimeDescription = javaVendor + " " + javaVersion;
		this.view.addTestResult(DiagnosticTests.JAVA_RUNTIME, true,
				javaRuntimeDescription);
	}

	private void osDiagnosticTest() {
		String osName = System.getProperty("os.name");
		String osVersion = System.getProperty("os.version");
		String osArch = System.getProperty("os.arch");
		String osDescription = osName + " " + osVersion + " (" + osArch + ")";
		this.view.addTestResult(DiagnosticTests.OS, true, osDescription);
	}

	private void browserDiagnosticTest() {
		ClassLoader classLoader = Controller.class.getClassLoader();
		Class<?> jsObjectClass;
		try {
			jsObjectClass = classLoader
					.loadClass("netscape.javascript.JSObject");
		} catch (ClassNotFoundException e) {
			addDetailMessage("JSObject class not found");
			addDetailMessage("not running inside a browser?");
			this.view.addTestResult(DiagnosticTests.BROWSER, false, e
					.getMessage());
			return;
		}
		try {
			Method getWindowMethod = jsObjectClass.getMethod("getWindow",
					new Class<?>[] { java.applet.Applet.class });
			Method getMemberMethod = jsObjectClass.getMethod("getMember",
					new Class<?>[] { String.class });
			Object windowJSObject = getWindowMethod.invoke(null, this.runtime
					.getApplet());
			Object navigatorJSObject = getMemberMethod.invoke(windowJSObject,
					"navigator");
			Object userAgent = getMemberMethod.invoke(navigatorJSObject,
					"userAgent");
			addDetailMessage("user agent: " + userAgent);
			this.view.addTestResult(DiagnosticTests.BROWSER, true, userAgent
					.toString());
		} catch (Exception e) {
			this.view.addTestResult(DiagnosticTests.BROWSER, false, e
					.getMessage());
			return;
		}
	}

	private void mscapiDiagnosticTest(X509Certificate authnCertificate) {
		String osName = System.getProperty("os.name");
		if (false == osName.startsWith("Windows")) {
			this.view
					.addDetailMessage("skipping MSCAPI test as we're not on windows");
			return;
		}
		KeyStore keyStore;
		Enumeration<String> aliases;
		try {
			keyStore = KeyStore.getInstance("Windows-MY");
			keyStore.load(null, null);
			aliases = keyStore.aliases();
		} catch (Exception e) {
			this.view.addDetailMessage("error loading MSCAPI keystore: "
					+ e.getMessage());
			this.view.addTestResult(DiagnosticTests.MSCAPI, false, e
					.getMessage());
			return;
		}
		String eIDSubjectName = null;
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			this.view.addDetailMessage("alias: " + alias);
			X509Certificate certificate;
			try {
				certificate = (X509Certificate) keyStore.getCertificate(alias);
			} catch (KeyStoreException e) {
				this.view.addDetailMessage("error loading MSCAPI certificate: "
						+ e.getMessage());
				this.view.addTestResult(DiagnosticTests.MSCAPI, false, e
						.getMessage());
				return;
			}

			if (certificate.equals(authnCertificate)) {
				String subjectName = certificate.getSubjectX500Principal()
						.toString();
				eIDSubjectName = subjectName;
			}
		}
		if (null == eIDSubjectName) {
			this.view.addTestResult(DiagnosticTests.MSCAPI, false,
					"No eID certificate found in the Windows keystore");
			return;
		}
		this.view.addTestResult(DiagnosticTests.MSCAPI, true, eIDSubjectName);
	}

	private class ControllerDiagnosticCallbackHandler implements
			DiagnosticCallbackHandler {

		public void addTestResult(DiagnosticTests test, boolean success,
				String information) {
			Controller.this.view.addTestResult(test, success, information);
		}
	}

	private SignCertificatesDataMessage performSignCertificatesOperation()
			throws Exception {
		setStatusMessage(Status.NORMAL, MESSAGE_ID.DETECTING_CARD);
		try {
			if (false == this.pkcs11Eid.isEidPresent()) {
				setStatusMessage(Status.NORMAL, MESSAGE_ID.INSERT_CARD_QUESTION);
				this.pkcs11Eid.waitForEidPresent();
			}
		} catch (PKCS11NotFoundException e) {
			addDetailMessage("eID Middleware PKCS#11 library not found.");
			if (null != this.pcscEidSpi) {
				addDetailMessage("fallback to PC/SC signing...");
				return performPcscSignCertificatesOperation();
			}
			throw new PKCS11NotFoundException();
		}
		setStatusMessage(Status.NORMAL, MESSAGE_ID.READING_IDENTITY);
		PrivateKeyEntry privateKeyEntry = this.pkcs11Eid
				.getPrivateKeyEntry("Signature");
		X509Certificate[] certificateChain = (X509Certificate[]) privateKeyEntry
				.getCertificateChain();
		this.pkcs11Eid.close();
		SignCertificatesDataMessage signCertificatesDataMessage = new SignCertificatesDataMessage(
				certificateChain);
		return signCertificatesDataMessage;
	}

	private SignCertificatesDataMessage performPcscSignCertificatesOperation()
			throws Exception {
		waitForEIdCard();
		byte[] signCertFile;
		byte[] citizenCaCertFile;
		byte[] rootCaCertFile;
		try {
			setStatusMessage(Status.NORMAL, MESSAGE_ID.READING_IDENTITY);
			signCertFile = this.pcscEidSpi.readFile(PcscEid.SIGN_CERT_FILE_ID);
			addDetailMessage("size sign cert file: " + signCertFile.length);
			citizenCaCertFile = this.pcscEidSpi
					.readFile(PcscEid.CA_CERT_FILE_ID);
			addDetailMessage("size citizen CA cert file: "
					+ citizenCaCertFile.length);
			rootCaCertFile = this.pcscEidSpi
					.readFile(PcscEid.ROOT_CERT_FILE_ID);
			addDetailMessage("size root CA cert file: " + rootCaCertFile.length);
		} finally {
			this.pcscEidSpi.close();
		}
		SignCertificatesDataMessage signCertificatesDataMessage = new SignCertificatesDataMessage(
				signCertFile, citizenCaCertFile, rootCaCertFile);
		return signCertificatesDataMessage;
	}

	private void kioskMode() throws IllegalArgumentException,
			SecurityException, IOException, PKCS11Exception,
			InterruptedException, NoSuchFieldException, IllegalAccessException,
			InvocationTargetException, NoSuchMethodException, Exception {
		addDetailMessage("entering Kiosk Mode...");
		this.view.setStatusMessage(Status.NORMAL,
				Messages.MESSAGE_ID.KIOSK_MODE);
		while (true) {
			try {
				if (false == this.pkcs11Eid.isEidPresent()) {
					this.pkcs11Eid.waitForEidPresent();
				}
				addDetailMessage("waiting for card removal...");
				this.pkcs11Eid.removeCard();
			} catch (PKCS11NotFoundException e) {
				addDetailMessage("fallback to PC/SC interface...");
				if (null == this.pcscEidSpi) {
					addDetailMessage("no PC/SC interface fallback possible.");
					throw e;
				}
				if (false == this.pcscEidSpi.isEidPresent()) {
					this.pcscEidSpi.waitForEidPresent();
				}
				addDetailMessage("waiting for card removal...");
				this.pcscEidSpi.removeCard();
			}
			addDetailMessage("card removed");
			ClassLoader classLoader = Controller.class.getClassLoader();
			Class<?> jsObjectClass;
			try {
				jsObjectClass = classLoader
						.loadClass("netscape.javascript.JSObject");
			} catch (ClassNotFoundException e) {
				addDetailMessage("JSObject class not found");
				addDetailMessage("not running inside a browser?");
				continue;
			}
			Method getWindowMethod = jsObjectClass.getMethod("getWindow",
					new Class<?>[] { java.applet.Applet.class });
			Object jsObject = getWindowMethod.invoke(null, this.runtime
					.getApplet());
			Method callMethod = jsObjectClass.getMethod("call", new Class<?>[] {
					String.class, Class.forName("[Ljava.lang.Object;") });
			String removeCardCallback = this.runtime
					.getParameter("RemoveCardCallback");
			if (null != removeCardCallback) {
				addDetailMessage("invoking javascript callback: "
						+ removeCardCallback);
				callMethod
						.invoke(jsObject, removeCardCallback, new Object[] {});
			} else {
				addDetailMessage("missing RemoveCardCallback parameter");
			}
		}
	}

	/**
	 * We're not accepting MD5.
	 */
	private final String[] SUPPORTED_FILES_DIGEST_ALGOS = new String[] {
			"SHA1", "SHA-1", "SHA-256", "SHA-384", "SHA-512" };

	private Object performFilesDigestOperation(String filesDigestAlgo)
			throws NoSuchAlgorithmException, IOException {
		addDetailMessage("files digest algorithm: " + filesDigestAlgo);

		boolean isSupportedFilesDigestAlgo = false;
		for (String supportedFilesDigestAlgo : SUPPORTED_FILES_DIGEST_ALGOS) {
			if (supportedFilesDigestAlgo.equals(filesDigestAlgo)) {
				isSupportedFilesDigestAlgo = true;
				break;
			}
		}
		if (false == isSupportedFilesDigestAlgo) {
			throw new SecurityException("files digest algo not supported: "
					+ filesDigestAlgo);
		}

		MessageDigest messageDigest = MessageDigest
				.getInstance(filesDigestAlgo);

		setStatusMessage(Status.NORMAL, MESSAGE_ID.SELECT_FILES);
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setMultiSelectionEnabled(true);
		int returnCode = fileChooser.showDialog(getParentComponent(),
				this.messages.getMessage(MESSAGE_ID.SELECT_FILES));
		if (JFileChooser.APPROVE_OPTION != returnCode) {
			throw new RuntimeException("file selection aborted");
		}

		setStatusMessage(Status.NORMAL, MESSAGE_ID.DIGESTING_FILES);

		FileDigestsDataMessage fileDigestsDataMessage = new FileDigestsDataMessage();
		fileDigestsDataMessage.fileDigestInfos = new LinkedList<String>();
		File[] selectedFiles = fileChooser.getSelectedFiles();
		long totalSize = 0;
		for (File selectedFile : selectedFiles) {
			totalSize += selectedFile.length();
		}
		final int BUFFER_SIZE = 1024 * 10;
		int progressMax = (int) (totalSize / BUFFER_SIZE);
		this.view.resetProgress(progressMax);
		addDetailMessage("total data size to digest: " + (totalSize / 1024)
				+ " KiB");
		for (File selectedFile : selectedFiles) {
			fileDigestsDataMessage.fileDigestInfos.add(filesDigestAlgo);
			long fileSize = selectedFile.length();
			addDetailMessage(selectedFile.getAbsolutePath() + ": "
					+ (fileSize / 1024) + " KiB");
			FileInputStream fileInputStream = new FileInputStream(selectedFile);
			DigestInputStream digestInputStream = new DigestInputStream(
					fileInputStream, messageDigest);
			byte[] buffer = new byte[BUFFER_SIZE];
			while (-1 != digestInputStream.read(buffer)) {
				this.view.increaseProgress();
			}
			digestInputStream.close();
			byte[] fileDigestValue = messageDigest.digest();
			messageDigest.reset();
			String fileDigest = toHex(fileDigestValue);
			fileDigestsDataMessage.fileDigestInfos.add(fileDigest);
			fileDigestsDataMessage.fileDigestInfos.add(selectedFile.getName());
		}
		this.view.setProgressIndeterminate();
		Object resultMessage = sendMessage(fileDigestsDataMessage);
		return resultMessage;
	}

	public static String toHex(byte[] data) {
		StringBuffer stringBuffer = new StringBuffer();
		for (byte b : data) {
			stringBuffer.append(toHex(b >> 4));
			stringBuffer.append(toHex(b));
		}
		return stringBuffer.toString();
	}

	private static char toHex(int value) {
		value &= 0xf;
		switch (value) {
		case 10:
			return 'A';
		case 11:
			return 'B';
		case 12:
			return 'C';
		case 13:
			return 'D';
		case 14:
			return 'E';
		case 15:
			return 'F';
		default:
			return (char) ('0' + value);
		}

	}

	private void performEidSignOperation(SignRequestMessage signRequestMessage)
			throws Exception {
		boolean logoff = signRequestMessage.logoff;
		boolean removeCard = signRequestMessage.removeCard;
		boolean requireSecureReader = signRequestMessage.requireSecureReader;
		addDetailMessage("logoff: " + logoff);
		addDetailMessage("remove card: " + removeCard);
		addDetailMessage("require secure smart card reader: "
				+ requireSecureReader);
		setStatusMessage(Status.NORMAL, MESSAGE_ID.DETECTING_CARD);
		if (requireSecureReader) {
			if (null != this.pcscEidSpi) {
				performEidPcscSignOperation(signRequestMessage,
						requireSecureReader);
				return;
			}
		}
		try {
			if (false == this.pkcs11Eid.isEidPresent()) {
				setStatusMessage(Status.NORMAL, MESSAGE_ID.INSERT_CARD_QUESTION);
				this.pkcs11Eid.waitForEidPresent();
			}
		} catch (PKCS11NotFoundException e) {
			addDetailMessage("eID Middleware PKCS#11 library not found.");
			if (null != this.pcscEidSpi) {
				addDetailMessage("fallback to PC/SC signing...");
				performEidPcscSignOperation(signRequestMessage,
						requireSecureReader);
				return;
			}
			throw new PKCS11NotFoundException();
		}
		setStatusMessage(Status.NORMAL, MESSAGE_ID.SIGNING);

		String logoffReaderName;
		if (logoff) {
			if (null == this.pcscEidSpi) {
				/*
				 * We cannot logoff via PC/SC so we remove the card via PKCS#11.
				 */
				removeCard = true;
				logoffReaderName = null;
			} else {
				if (removeCard) {
					/*
					 * No need to logoff a removed card.
					 */
					logoffReaderName = null;
				} else {
					logoffReaderName = this.pkcs11Eid.getSlotDescription();
				}
			}
		} else {
			logoffReaderName = null;
		}

		byte[] signatureValue;
		List<X509Certificate> signCertChain;
		try {
			/*
			 * Via next dialog we try to implement WYSIWYS using the digest
			 * description. Also showing the digest value is pointless.
			 */
			// TODO DRY refactoring
			int response = JOptionPane.showConfirmDialog(this
					.getParentComponent(), "OK to sign \""
					+ signRequestMessage.description + "\"?\n"
					+ "Signature algorithm: " + signRequestMessage.digestAlgo
					+ " with RSA", "Signature creation",
					JOptionPane.YES_NO_OPTION);
			// TODO i18n
			if (JOptionPane.OK_OPTION != response) {
				throw new SecurityException("sign operation aborted");
			}
			addDetailMessage("signing with algorithm: "
					+ signRequestMessage.digestAlgo + " with RSA");
			signatureValue = this.pkcs11Eid.sign(
					signRequestMessage.digestValue,
					signRequestMessage.digestAlgo);
			signCertChain = this.pkcs11Eid.getSignCertificateChain();
			if (removeCard) {
				setStatusMessage(Status.NORMAL, MESSAGE_ID.REMOVE_CARD);
				this.pkcs11Eid.removeCard();
			}
		} finally {
			/*
			 * We really need to remove the SunPKCS11 security provider, else a
			 * following eID signature will fail.
			 */
			this.pkcs11Eid.close();
			if (null != logoffReaderName) {
				this.pcscEidSpi.logoff(logoffReaderName);
			}
		}
		SignatureDataMessage signatureDataMessage = new SignatureDataMessage(
				signatureValue, signCertChain);
		Object responseMessage = sendMessage(signatureDataMessage);
		if (false == (responseMessage instanceof FinishedMessage)) {
			throw new RuntimeException("finish expected");
		}
	}

	private void performEidPcscSignOperation(
			SignRequestMessage signRequestMessage, boolean requireSecureReader)
			throws Exception {
		waitForEIdCard();

		setStatusMessage(Status.NORMAL, MESSAGE_ID.SIGNING);
		byte[] signatureValue;
		byte[] signCertFile;
		byte[] citizenCaCertFile;
		byte[] rootCaCertFile;
		try {
			/*
			 * Via next dialog we try to implement WYSIWYS using the digest
			 * description. Also showing the digest value is pointless.
			 */
			// TODO DRY refactoring
			int response = JOptionPane.showConfirmDialog(this
					.getParentComponent(), "OK to sign \""
					+ signRequestMessage.description + "\"?\n"
					+ "Signature algorithm: " + signRequestMessage.digestAlgo
					+ " with RSA", "Signature creation",
					JOptionPane.YES_NO_OPTION);
			// TODO i18n
			if (JOptionPane.OK_OPTION != response) {
				throw new SecurityException("sign operation aborted");
			}
			signatureValue = this.pcscEidSpi.sign(
					signRequestMessage.digestValue,
					signRequestMessage.digestAlgo, requireSecureReader);

			int maxProgress = 0;
			maxProgress += (1050 / 255) + 1; // sign cert file
			maxProgress += (1050 / 255) + 1; // CA cert file
			maxProgress += (1050 / 255) + 1; // Root cert file
			this.view.resetProgress(maxProgress);

			signCertFile = this.pcscEidSpi.readFile(PcscEid.SIGN_CERT_FILE_ID);
			citizenCaCertFile = this.pcscEidSpi
					.readFile(PcscEid.CA_CERT_FILE_ID);
			rootCaCertFile = this.pcscEidSpi
					.readFile(PcscEid.ROOT_CERT_FILE_ID);

			this.view.setProgressIndeterminate();

			if (signRequestMessage.logoff && !signRequestMessage.removeCard) {
				this.pcscEidSpi.logoff();
			}
			if (signRequestMessage.removeCard) {
				setStatusMessage(Status.NORMAL, MESSAGE_ID.REMOVE_CARD);
				this.pcscEidSpi.removeCard();
			}
		} finally {
			this.pcscEidSpi.close();
		}

		SignatureDataMessage signatureDataMessage = new SignatureDataMessage(
				signatureValue, signCertFile, citizenCaCertFile, rootCaCertFile);
		Object responseMessage = sendMessage(signatureDataMessage);
		if (false == (responseMessage instanceof FinishedMessage)) {
			throw new RuntimeException("finish expected");
		}
	}

	private void administration(boolean unblockPin, boolean changePin,
			boolean logoff, boolean removeCard, boolean requireSecureReader)
			throws Exception {
		waitForEIdCard();
		try {
			if (unblockPin) {
				setStatusMessage(Status.NORMAL, Messages.MESSAGE_ID.PIN_UNBLOCK);
				this.pcscEidSpi.unblockPin(requireSecureReader);
			}
			if (changePin) {
				setStatusMessage(Status.NORMAL, Messages.MESSAGE_ID.PIN_CHANGE);
				this.pcscEidSpi.changePin(requireSecureReader);
			}
			if (logoff) {
				this.pcscEidSpi.logoff();
			}
			if (removeCard) {
				setStatusMessage(Status.NORMAL, MESSAGE_ID.REMOVE_CARD);
				this.pcscEidSpi.removeCard();
			}
		} finally {
			/*
			 * Required to release the exclusive access lock. Else a next
			 * execution of the eID Applet will fail.
			 */
			this.pcscEidSpi.close();
		}
	}

	private FinishedMessage performEidAuthnOperation(
			AuthenticationRequestMessage authnRequest) throws Exception {
		byte[] challenge = authnRequest.challenge;
		boolean removeCard = authnRequest.removeCard;
		boolean includeHostname = authnRequest.includeHostname;
		boolean includeInetAddress = authnRequest.includeInetAddress;
		boolean logoff = authnRequest.logoff;
		boolean preLogoff = authnRequest.preLogoff;
		boolean sessionIdChannelBinding = authnRequest.sessionIdChannelBinding;
		boolean serverCertificateChannelBinding = authnRequest.serverCertificateChannelBinding;
		boolean includeIdentity = authnRequest.includeIdentity;
		boolean includeCertificates = authnRequest.includeCertificates;
		boolean includeAddress = authnRequest.includeAddress;
		boolean includePhoto = authnRequest.includePhoto;
		boolean includeIntegrityData = authnRequest.includeIntegrityData;
		boolean requireSecureReader = authnRequest.requireSecureReader;
		if (challenge.length < 20) {
			throw new SecurityException(
					"challenge should be at least 20 bytes long.");
		}
		addDetailMessage("include hostname: " + includeHostname);
		addDetailMessage("include inet address: " + includeInetAddress);
		addDetailMessage("remove card after authn: " + removeCard);
		addDetailMessage("logoff: " + logoff);
		addDetailMessage("pre-logoff: " + preLogoff);
		addDetailMessage("TLS session Id channel binding: "
				+ sessionIdChannelBinding);
		addDetailMessage("server certificate channel binding: "
				+ serverCertificateChannelBinding);
		addDetailMessage("include identity: " + includeIdentity);
		addDetailMessage("include certificates: " + includeCertificates);
		addDetailMessage("include address: " + includeAddress);
		addDetailMessage("include photo: " + includePhoto);
		addDetailMessage("include integrity data: " + includeIntegrityData);
		addDetailMessage("require secure smart card reader: "
				+ requireSecureReader);

		SecureRandom secureRandom = new SecureRandom();
		byte[] salt = new byte[20];
		secureRandom.nextBytes(salt);

		String hostname;
		if (includeHostname) {
			/*
			 * We extract the hostname from the web page location in which this
			 * eID Applet is embedded.
			 */
			URL documentBase = this.runtime.getDocumentBase();
			hostname = documentBase.getHost();
			addDetailMessage("hostname: " + hostname);
		} else {
			hostname = null;
		}

		InetAddress inetAddress;
		if (includeInetAddress) {
			URL documentBase = this.runtime.getDocumentBase();
			inetAddress = InetAddress.getByName(documentBase.getHost());
			addDetailMessage("inet address: " + inetAddress.getHostAddress());
		} else {
			inetAddress = null;
		}

		byte[] sessionId;
		if (sessionIdChannelBinding) {
			sessionId = AppletSSLSocketFactory.getActualSessionId();
		} else {
			sessionId = null;
		}

		byte[] encodedServerCertificate;
		if (serverCertificateChannelBinding) {
			encodedServerCertificate = AppletSSLSocketFactory
					.getActualEncodedServerCertificate();
		} else {
			encodedServerCertificate = null;
		}

		AuthenticationContract authenticationContract = new AuthenticationContract(
				salt, hostname, inetAddress, sessionId,
				encodedServerCertificate, challenge);
		byte[] toBeSigned = authenticationContract.calculateToBeSigned();

		setStatusMessage(Status.NORMAL, MESSAGE_ID.DETECTING_CARD);
		if (includeIdentity || includeAddress || includePhoto
				|| includeCertificates || requireSecureReader) {
			if (null != this.pcscEidSpi) {
				FinishedMessage finishedMessage = performEidPcscAuthnOperation(
						salt, sessionId, toBeSigned, logoff, preLogoff,
						removeCard, includeIdentity, includeCertificates,
						includeAddress, includePhoto, includeIntegrityData,
						encodedServerCertificate, requireSecureReader);
				return finishedMessage;
			}
		}
		try {
			if (false == this.pkcs11Eid.isEidPresent()) {
				setStatusMessage(Status.NORMAL, MESSAGE_ID.INSERT_CARD_QUESTION);
				this.pkcs11Eid.waitForEidPresent();
			}
		} catch (PKCS11NotFoundException e) {
			addDetailMessage("eID Middleware PKCS#11 library not found.");
			if (null != this.pcscEidSpi) {
				addDetailMessage("fallback to PC/SC interface for authentication...");
				FinishedMessage finishedMessage = performEidPcscAuthnOperation(
						salt, sessionId, toBeSigned, logoff, preLogoff,
						removeCard, includeIdentity, includeCertificates,
						includeAddress, includePhoto, includeIntegrityData,
						encodedServerCertificate, requireSecureReader);
				return finishedMessage;
			}
			throw new PKCS11NotFoundException();
		}
		setStatusMessage(Status.NORMAL, MESSAGE_ID.AUTHENTICATING);

		String logoffReaderName;
		if (logoff) {
			if (null == this.pcscEidSpi) {
				/*
				 * We cannot logoff via PC/SC so we remove the card via PKCS#11.
				 */
				removeCard = true;
				logoffReaderName = null;
			} else {
				if (removeCard) {
					/*
					 * No need to logoff a removed card.
					 */
					logoffReaderName = null;
				} else {
					logoffReaderName = this.pkcs11Eid.getSlotDescription();
				}
			}
		} else {
			logoffReaderName = null;
		}

		if (preLogoff) {
			if (null != this.pcscEidSpi) {
				this.view.addDetailMessage("performing a pre-logoff");
				String readerName = logoffReaderName;
				if (null == readerName) {
					readerName = this.pkcs11Eid.getSlotDescription();
				}
				this.pcscEidSpi.logoff(readerName);
			} else {
				this.view.addDetailMessage("cannot perform a pre-logoff");
			}
		}

		byte[] signatureValue;
		List<X509Certificate> authnCertChain;
		try {
			signatureValue = this.pkcs11Eid.signAuthn(toBeSigned);
			authnCertChain = this.pkcs11Eid.getAuthnCertificateChain();
			if (removeCard) {
				setStatusMessage(Status.NORMAL, MESSAGE_ID.REMOVE_CARD);
				this.pkcs11Eid.removeCard();
			}
		} finally {
			/*
			 * We really need to remove the SunPKCS11 security provider, else a
			 * following eID authentication will fail.
			 */
			this.pkcs11Eid.close();
			if (null != logoffReaderName) {
				this.pcscEidSpi.logoff(logoffReaderName);
			}
		}

		AuthenticationDataMessage authenticationDataMessage = new AuthenticationDataMessage(
				salt, sessionId, signatureValue, authnCertChain, null, null,
				null, null, null, null, null, encodedServerCertificate);
		Object responseMessage = sendMessage(authenticationDataMessage);
		if (false == (responseMessage instanceof FinishedMessage)) {
			throw new RuntimeException("finish expected");
		}
		FinishedMessage finishedMessage = (FinishedMessage) responseMessage;
		return finishedMessage;
	}

	private FinishedMessage performEidPcscAuthnOperation(byte[] salt,
			byte[] sessionId, byte[] toBeSigned, boolean logoff,
			boolean preLogoff, boolean removeCard, boolean includeIdentity,
			boolean includeCertificates, boolean includeAddress,
			boolean includePhoto, boolean includeIntegrityData,
			byte[] encodedServerCertificate, boolean requireSecureReader)
			throws Exception {
		waitForEIdCard();

		setStatusMessage(Status.NORMAL, MESSAGE_ID.AUTHENTICATING);

		if (includeIdentity || includeAddress || includePhoto) {
			boolean response = this.view.privacyQuestion(includeAddress,
					includePhoto, null);
			if (false == response) {
				this.pcscEidSpi.close();
				throw new SecurityException(
						"user did not agree to release eID identity information");
			}
		}

		byte[] signatureValue;
		byte[] identityData = null;
		byte[] addressData = null;
		byte[] photoData = null;
		byte[] identitySignatureData = null;
		byte[] addressSignatureData = null;
		byte[] rrnCertData = null;
		byte[] authnCertFile = null;
		byte[] signCertFile = null;
		byte[] citCaCertFile = null;
		byte[] rootCaCertFile = null;
		try {
			if (preLogoff) {
				/*
				 * Use the PreLogoff feature to make sure that the user has to
				 * enter his PIN code on each authentication request.
				 */
				this.view.addDetailMessage("performing a pre-logoff");
				this.pcscEidSpi.logoff();
			}
			signatureValue = this.pcscEidSpi.signAuthn(toBeSigned,
					requireSecureReader);

			int maxProgress = 0;
			maxProgress += (1050 / 255) + 1; // authn cert file
			maxProgress += (1050 / 255) + 1; // CA cert file
			maxProgress += (1050 / 255) + 1; // Root cert file
			if (includeIdentity) {
				maxProgress++;
			}
			if (includeAddress) {
				maxProgress++;
			}
			if (includePhoto) {
				maxProgress += 3000 / 255;
			}
			if (includeIntegrityData) {
				if (includeIdentity) {
					maxProgress++; // identity signature file
				}
				if (includeAddress) {
					maxProgress++; // address signature file
				}
				maxProgress += (1050 / 255) + 1; // RRN certificate file
			}
			this.view.resetProgress(maxProgress);

			/*
			 * Next design pattern is the only way to handle the case where
			 * multiple application access the smart card at the same time.
			 */
			TaskRunner taskRunner = new TaskRunner(this.pcscEidSpi, this.view);
			authnCertFile = taskRunner.run(new Task<byte[]>() {
				public byte[] run() throws Exception {
					return Controller.this.pcscEidSpi
							.readFile(PcscEid.AUTHN_CERT_FILE_ID);
				}
			});
			citCaCertFile = taskRunner.run(new Task<byte[]>() {
				public byte[] run() throws Exception {
					return Controller.this.pcscEidSpi
							.readFile(PcscEid.CA_CERT_FILE_ID);
				}
			});
			rootCaCertFile = taskRunner.run(new Task<byte[]>() {
				public byte[] run() throws Exception {
					return Controller.this.pcscEidSpi
							.readFile(PcscEid.ROOT_CERT_FILE_ID);
				}
			});
			if (includeCertificates) {
				addDetailMessage("reading sign certificate file...");
				signCertFile = taskRunner.run(new Task<byte[]>() {
					public byte[] run() throws Exception {
						return Controller.this.pcscEidSpi
								.readFile(PcscEid.SIGN_CERT_FILE_ID);
					}
				});
				addDetailMessage("size non-repud cert file: "
						+ signCertFile.length);
			}

			if (includeIdentity || includeAddress || includePhoto) {
				setStatusMessage(Status.NORMAL, MESSAGE_ID.READING_IDENTITY);
			}

			if (includeIdentity) {
				identityData = taskRunner.run(new Task<byte[]>() {
					public byte[] run() throws Exception {
						return Controller.this.pcscEidSpi
								.readFile(PcscEid.IDENTITY_FILE_ID);
					}
				});
			}
			if (includeAddress) {
				addressData = taskRunner.run(new Task<byte[]>() {
					public byte[] run() throws Exception {
						return Controller.this.pcscEidSpi
								.readFile(PcscEid.ADDRESS_FILE_ID);
					}
				});
			}
			if (includePhoto) {
				photoData = taskRunner.run(new Task<byte[]>() {
					public byte[] run() throws Exception {
						return Controller.this.pcscEidSpi
								.readFile(PcscEid.PHOTO_FILE_ID);
					}
				});
			}
			if (includeIntegrityData) {
				if (includeIdentity) {
					identitySignatureData = taskRunner.run(new Task<byte[]>() {
						public byte[] run() throws Exception {
							return Controller.this.pcscEidSpi
									.readFile(PcscEid.IDENTITY_SIGN_FILE_ID);
						}
					});
				}
				if (includeAddress) {
					addressSignatureData = taskRunner.run(new Task<byte[]>() {
						public byte[] run() throws Exception {
							return Controller.this.pcscEidSpi
									.readFile(PcscEid.ADDRESS_SIGN_FILE_ID);
						}
					});
				}
				rrnCertData = taskRunner.run(new Task<byte[]>() {
					public byte[] run() throws Exception {
						return Controller.this.pcscEidSpi
								.readFile(PcscEid.RRN_CERT_FILE_ID);
					}
				});
			}

			this.view.setProgressIndeterminate();

			if (logoff && !removeCard) {
				this.pcscEidSpi.logoff();
			}
			if (removeCard) {
				setStatusMessage(Status.NORMAL, MESSAGE_ID.REMOVE_CARD);
				this.pcscEidSpi.removeCard();
			}
		} finally {
			this.pcscEidSpi.close();
		}

		AuthenticationDataMessage authenticationDataMessage = new AuthenticationDataMessage(
				salt, sessionId, signatureValue, authnCertFile, citCaCertFile,
				rootCaCertFile, signCertFile, identityData, addressData,
				photoData, identitySignatureData, addressSignatureData,
				rrnCertData, encodedServerCertificate);
		Object responseMessage = sendMessage(authenticationDataMessage);
		if (false == (responseMessage instanceof FinishedMessage)) {
			throw new RuntimeException("finish expected");
		}
		FinishedMessage finishedMessage = (FinishedMessage) responseMessage;
		return finishedMessage;
	}

	private void printEnvironment() {
		Version version = new Version();
		addDetailMessage("eID browser applet version: " + version.getVersion());
		addDetailMessage("Java version: " + System.getProperty("java.version"));
		addDetailMessage("Java vendor: " + System.getProperty("java.vendor"));
		addDetailMessage("OS: " + System.getProperty("os.name"));
		addDetailMessage("OS version: " + System.getProperty("os.version"));
		addDetailMessage("OS arch: " + System.getProperty("os.arch"));
		addDetailMessage("Web application URL: "
				+ this.runtime.getDocumentBase());
		addDetailMessage("Current time: " + new Date());
		// XXX when using SunPKCS11 we only accept the Sun JRE and OpenJDK

		/*
		 * Next we check for the presence of the session cookie.
		 */
		CookieHandler cookieHandler = CookieHandler.getDefault();
		if (null != cookieHandler) {
			URL documentBase = this.runtime.getApplet().getDocumentBase();
			try {
				Map<String, List<String>> headers = cookieHandler.get(
						documentBase.toURI(),
						new HashMap<String, List<String>>());
				List<String> cookieHeaderValues = headers.get("Cookie");
				if (null == cookieHeaderValues || cookieHeaderValues.isEmpty()) {
					addDetailMessage("ERROR: no session cookie detected!");
				} else {
					/*
					 * Of course we don't print out the session cookie...
					 */
					addDetailMessage("session cookie detected");
				}
			} catch (Exception e) {
				addDetailMessage("error getting cookies from default cookie handler");
			}
		}
	}

	public void addDetailMessage(String detailMessage) {
		this.view.addDetailMessage(detailMessage);
	}

	private class PcscEidObserver implements Observer {

		public void update(Observable observable, Object arg) {
			Controller.this.view.increaseProgress();
		}
	}

	private void performEidIdentificationOperation(boolean includeAddress,
			boolean includePhoto, boolean includeIntegrityData,
			boolean includeCertificates, boolean removeCard,
			String identityDataUsage) throws Exception {
		waitForEIdCard();

		setStatusMessage(Status.NORMAL, MESSAGE_ID.READING_IDENTITY);

		boolean response = this.view.privacyQuestion(includeAddress,
				includePhoto, identityDataUsage);
		if (false == response) {
			this.pcscEidSpi.close();
			throw new SecurityException(
					"user did not agree to release eID identity information");
		}

		addDetailMessage("Reading identity file...");

		/*
		 * Calculate the maximum progress bar indication
		 */
		int maxProgress = 1; // identity file
		if (includeAddress) {
			maxProgress++;
		}
		if (includePhoto) {
			maxProgress += 3000 / 255;
		}
		if (includeIntegrityData) {
			maxProgress++; // identity signature file
			if (includeAddress) {
				maxProgress++; // address signature file
			}
			maxProgress += (1050 / 255) + 1; // RRN certificate file
			maxProgress += (1050 / 255) + 1; // Root certificate file
		}
		if (includeCertificates) {
			maxProgress += (1050 / 255) + 1; // authn cert file
			maxProgress += (1050 / 255) + 1; // sign cert file
			maxProgress += (1050 / 255) + 1; // citizen CA cert file
			if (false == includeIntegrityData) {
				maxProgress += (1050 / 255) + 1; // root CA cert file
			}
		}
		this.view.resetProgress(maxProgress);

		TaskRunner taskRunner = new TaskRunner(this.pcscEidSpi, this.view);
		/*
		 * Next design pattern is the only way to handle the case where multiple
		 * application access the smart card at the same time.
		 */
		byte[] idFile = taskRunner.run(new Task<byte[]>() {
			public byte[] run() throws Exception {
				return Controller.this.pcscEidSpi
						.readFile(PcscEid.IDENTITY_FILE_ID);
			}
		});
		addDetailMessage("Size identity file: " + idFile.length);

		byte[] addressFile = null;
		if (includeAddress) {
			addDetailMessage("Read address file...");
			addressFile = taskRunner.run(new Task<byte[]>() {

				public byte[] run() throws Exception {
					return Controller.this.pcscEidSpi
							.readFile(PcscEid.ADDRESS_FILE_ID);
				}
			});
			addDetailMessage("Size address file: " + addressFile.length);
		}

		byte[] photoFile = null;
		if (includePhoto) {
			addDetailMessage("Read photo file...");
			photoFile = taskRunner.run(new Task<byte[]>() {

				public byte[] run() throws Exception {
					return Controller.this.pcscEidSpi
							.readFile(PcscEid.PHOTO_FILE_ID);
				}
			});
		}

		byte[] identitySignatureFile = null;
		byte[] addressSignatureFile = null;
		byte[] rrnCertFile = null;
		byte[] rootCertFile = null;
		if (includeIntegrityData) {
			addDetailMessage("Read identity signature file...");
			identitySignatureFile = taskRunner.run(new Task<byte[]>() {
				public byte[] run() throws Exception {
					return Controller.this.pcscEidSpi
							.readFile(PcscEid.IDENTITY_SIGN_FILE_ID);
				}
			});
			if (includeAddress) {
				addDetailMessage("Read address signature file...");
				addressSignatureFile = taskRunner.run(new Task<byte[]>() {
					public byte[] run() throws Exception {
						return Controller.this.pcscEidSpi
								.readFile(PcscEid.ADDRESS_SIGN_FILE_ID);
					}
				});
			}
			addDetailMessage("Read national registry certificate file...");
			rrnCertFile = taskRunner.run(new Task<byte[]>() {
				public byte[] run() throws Exception {
					return Controller.this.pcscEidSpi
							.readFile(PcscEid.RRN_CERT_FILE_ID);
				}
			});
			addDetailMessage("size RRN cert file: " + rrnCertFile.length);
			addDetailMessage("reading root certificate file...");
			rootCertFile = taskRunner.run(new Task<byte[]>() {
				public byte[] run() throws Exception {
					return Controller.this.pcscEidSpi
							.readFile(PcscEid.ROOT_CERT_FILE_ID);
				}
			});
			addDetailMessage("size Root CA cert file: " + rootCertFile.length);
		}

		byte[] authnCertFile = null;
		byte[] signCertFile = null;
		byte[] caCertFile = null;
		if (includeCertificates) {
			addDetailMessage("reading authn certificate file...");
			authnCertFile = taskRunner.run(new Task<byte[]>() {
				public byte[] run() throws Exception {
					return Controller.this.pcscEidSpi
							.readFile(PcscEid.AUTHN_CERT_FILE_ID);
				}
			});
			addDetailMessage("size authn cert file: " + authnCertFile.length);

			addDetailMessage("reading sign certificate file...");
			signCertFile = taskRunner.run(new Task<byte[]>() {
				public byte[] run() throws Exception {
					return Controller.this.pcscEidSpi
							.readFile(PcscEid.SIGN_CERT_FILE_ID);
				}
			});
			addDetailMessage("size non-repud cert file: " + signCertFile.length);

			addDetailMessage("reading citizen CA certificate file...");
			caCertFile = taskRunner.run(new Task<byte[]>() {
				public byte[] run() throws Exception {
					return Controller.this.pcscEidSpi
							.readFile(PcscEid.CA_CERT_FILE_ID);
				}
			});
			addDetailMessage("size Cit CA cert file: " + caCertFile.length);

			if (null == rootCertFile) {
				addDetailMessage("reading root certificate file...");
				rootCertFile = taskRunner.run(new Task<byte[]>() {
					public byte[] run() throws Exception {
						return Controller.this.pcscEidSpi
								.readFile(PcscEid.ROOT_CERT_FILE_ID);
					}
				});
				addDetailMessage("size Root CA cert file: "
						+ rootCertFile.length);
			}
		}

		this.view.setProgressIndeterminate();

		if (removeCard) {
			setStatusMessage(Status.NORMAL, MESSAGE_ID.REMOVE_CARD);
			this.pcscEidSpi.removeCard();
		}

		this.pcscEidSpi.close();

		setStatusMessage(Status.NORMAL, MESSAGE_ID.TRANSMITTING_IDENTITY);

		IdentityDataMessage identityData = new IdentityDataMessage(idFile,
				addressFile, photoFile, identitySignatureFile,
				addressSignatureFile, rrnCertFile, rootCertFile, authnCertFile,
				signCertFile, caCertFile);
		sendMessage(identityData, FinishedMessage.class);
	}

	private void waitForEIdCard() throws Exception {
		setStatusMessage(Status.NORMAL, MESSAGE_ID.DETECTING_CARD);
		if (false == this.pcscEidSpi.hasCardReader()) {
			setStatusMessage(Status.NORMAL, MESSAGE_ID.CONNECT_READER);
			this.pcscEidSpi.waitForCardReader();
		}
		if (false == this.pcscEidSpi.isEidPresent()) {
			setStatusMessage(Status.NORMAL, MESSAGE_ID.INSERT_CARD_QUESTION);
			this.pcscEidSpi.waitForEidPresent();
		}
	}

	public static final String APPLET_SERVICE_PARAM = "AppletService";

	private HttpURLConnection getServerConnection()
			throws MalformedURLException, IOException {
		String appletServiceParam = this.runtime
				.getParameter(APPLET_SERVICE_PARAM);
		if (null == appletServiceParam) {
			throw new IllegalArgumentException("no " + APPLET_SERVICE_PARAM
					+ " parameter specified");
		}

		URL appletServiceUrl = new URL(this.runtime.getDocumentBase(),
				appletServiceParam);

		/*
		 * Install our SSL socket factory.
		 */
		AppletSSLSocketFactory.installSocketFactory(this.view);

		HttpURLConnection connection = (HttpURLConnection) appletServiceUrl
				.openConnection();
		return connection;
	}

	private void setStatusMessage(Status status, Messages.MESSAGE_ID messageId) {
		this.view.setStatusMessage(status, messageId);
	}

	public Component getParentComponent() {
		return this.view.getParentComponent();
	}
}
