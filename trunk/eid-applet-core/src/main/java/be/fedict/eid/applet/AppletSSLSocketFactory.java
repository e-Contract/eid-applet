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

package be.fedict.eid.applet;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Arrays;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * eID Applet specific implementation of an SSL Socket Factory.
 * 
 * <p>
 * Makes sure that the SSL session doesn't change during eID Applet operations.
 * Gives us access to the SSL session identifier so we can implement secure
 * tunnel binding in our authentication protocol.
 * </p>
 * 
 * @author fcorneli
 * 
 */
public class AppletSSLSocketFactory extends SSLSocketFactory implements
		HandshakeCompletedListener {

	private final View view;

	private final SSLSocketFactory originalSslSocketFactory;

	private byte[] sslSessionId;

	public AppletSSLSocketFactory(View view,
			SSLSocketFactory originalSslSocketFactory) {
		this.view = view;
		this.originalSslSocketFactory = originalSslSocketFactory;
	}

	@Override
	public Socket createSocket(Socket s, String host, int port,
			boolean autoClose) throws IOException {
		Socket socket = this.originalSslSocketFactory.createSocket(s, host,
				port, autoClose);
		checkSocket(socket);
		return socket;
	}

	private void checkSocket(Socket socket) throws IOException {
		SSLSocket sslSocket = (SSLSocket) socket;
		sslSocket.addHandshakeCompletedListener(this);
		/*
		 * Retrieving the SSL session identifier via sslSocket.getSession()
		 * doesn't always work. Hence the need to also add an SSL handshake
		 * listener.
		 */
		SSLSession sslSession = sslSocket.getSession();
		String cipherSuite = sslSession.getCipherSuite();
		if ("SSL_NULL_WITH_NULL_NULL".equals(cipherSuite)) {
			/*
			 * Inside a browser we're depending on the SSL handshake listener to
			 * retrieve the SSL session identifier.
			 */
			return;
		}
		this.view.addDetailMessage("SSL cipher suite: " + cipherSuite);
		byte[] sslSessionId = sslSession.getId();
		if (null == this.sslSessionId) {
			this.sslSessionId = sslSessionId;
		} else {
			if (false == Arrays.equals(this.sslSessionId, sslSessionId)) {
				throw new IOException("SSL session mismatch");
			}
		}
	}

	@Override
	public String[] getDefaultCipherSuites() {
		return this.originalSslSocketFactory.getDefaultCipherSuites();
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return this.originalSslSocketFactory.getSupportedCipherSuites();
	}

	@Override
	public Socket createSocket(String host, int port) throws IOException,
			UnknownHostException {
		Socket socket = this.originalSslSocketFactory.createSocket(host, port);
		checkSocket(socket);
		return socket;
	}

	@Override
	public Socket createSocket(InetAddress host, int port) throws IOException {
		Socket socket = this.originalSslSocketFactory.createSocket(host, port);
		checkSocket(socket);
		return socket;
	}

	@Override
	public Socket createSocket(String host, int port, InetAddress localHost,
			int localPort) throws IOException, UnknownHostException {
		Socket socket = this.originalSslSocketFactory.createSocket(host, port,
				localHost, localPort);
		checkSocket(socket);
		return socket;
	}

	@Override
	public Socket createSocket(InetAddress host, int port,
			InetAddress localHost, int localPort) throws IOException {
		Socket socket = this.originalSslSocketFactory.createSocket(host, port,
				localHost, localPort);
		checkSocket(socket);
		return socket;
	}

	/**
	 * Gives back the SSL session identifier.
	 * 
	 * @return the SSL session Id.
	 */
	public byte[] getSessionId() {
		if (null == this.sslSessionId) {
			throw new IllegalStateException("SSL session identifier unknown");
		}
		return this.sslSessionId;
	}

	@Override
	public Socket createSocket() throws IOException {
		Socket socket = this.originalSslSocketFactory.createSocket();
		checkSocket(socket);
		return socket;
	}

	public void handshakeCompleted(HandshakeCompletedEvent event) {
		String cipherSuite = event.getCipherSuite();
		this.view.addDetailMessage("SSL cipher suite: " + cipherSuite);
		SSLSession sslSession = event.getSession();
		byte[] sslSessionId = sslSession.getId();
		if (null == this.sslSessionId) {
			this.sslSessionId = sslSessionId;
		} else {
			if (false == Arrays.equals(this.sslSessionId, sslSessionId)) {
				this.view.addDetailMessage("SSL session Id mismatch");
			}
		}
	}
}
