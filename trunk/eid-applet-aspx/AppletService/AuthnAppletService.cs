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

using System;
using System.Web;
using System.Web.SessionState;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


namespace Be.FedICT.EID.Applet.Service {
	
	public class AuthnAppletService : IHttpHandler, IRequiresSessionState {
		
		public AuthnAppletService() {	
		}
		
		public void ProcessRequest(HttpContext httpContext) {
			Log("process request");
			HttpRequest httpRequest = httpContext.Request;
			HttpResponse httpResponse = httpContext.Response;
			if ("GET".Equals(httpRequest.HttpMethod)) {
				httpResponse.Write("<html><body>The eID Applet Service should not be invoked directly.</body></html>");
				return;
			}
			if (!"POST".Equals(httpRequest.HttpMethod)) {
				httpResponse.StatusCode = 400; // bad request
				return;
			}
			String protocolVersion = httpRequest.Headers["X-AppletProtocol-Version"];
			if (!"1".Equals(protocolVersion)) {
				httpResponse.StatusCode = 400; // bad request
				return;
			}
			String messageType = httpRequest.Headers["X-AppletProtocol-Type"];
			if ("HelloMessage".Equals(messageType)) {
				httpContext.Session.Remove("Identifier");
				
				sendCommand("AuthenticationRequestMessage", httpResponse);
				Random random = new Random();
				byte[] challenge = new byte[20];
				random.NextBytes(challenge);
				httpResponse.BinaryWrite(challenge);
				return;
			}
			if ("AuthenticationDataMessage".Equals(messageType)) {
				String saltValueSizeString = httpRequest.Headers["X-AppletProtocol-SaltValueSize"];
				String signatureValueSizeString = httpRequest.Headers["X-AppletProtocol-SignatureValueSize"];
				int saltValueSize = Int32.Parse(saltValueSizeString);
				int signatureValueSize = Int32.Parse(signatureValueSizeString);
				
				Stream inputStream = httpRequest.InputStream;
				byte[] saltValue = new byte[saltValueSize]; 
				inputStream.Read(saltValue, 0, saltValueSize);
				
				byte[] signatureValue = new byte[signatureValueSize];
				inputStream.Read(signatureValue, 0, signatureValueSize);
				
				int bytesLeft = (int)(inputStream.Length - inputStream.Position);
				byte[] certsData = new byte[bytesLeft];
				inputStream.Read(certsData, 0, bytesLeft);
				
				X509Certificate2 certificate2 = new X509Certificate2(certsData);
				
				// TODO: verify signature
				RSACryptoServiceProvider rsaCryptoService = new RSACryptoServiceProvider();
				byte[] toBeSignedData = new byte[20]; // TODO
				//bool signatureResult = rsaCryptoService.VerifyData(toBeSignedData, CryptoConfig.MapNameToOID("SHA1"), signatureValue);
				//Log("signature result: " + signatureResult);
				
				// TODO: verify certificate validity
				
				X500DistinguishedName subjectName = certificate2.SubjectName;
				Log("subject: " + subjectName.Name);
				
				int commaIdx = subjectName.Name.IndexOf(",");
				int prefixSize = "OID.2.5.4.5=".Length;
				string identifier = subjectName.Name.Substring(prefixSize, commaIdx - prefixSize);
				httpContext.Session.Add("Identifier", identifier);
				sendCommand("FinishedMessage", httpResponse);
				return;
			}
		}
		
		public bool IsReusable {
			get {
				return true;
			}
		}
		
		private void Log(string message) {
			System.Console.WriteLine(message);
		}
		
		private void sendCommand(string command, HttpResponse httpResponse) {
			httpResponse.AddHeader("X-AppletProtocol-Version", "1");
			httpResponse.AddHeader("X-AppletProtocol-Type", command);
		}
	}
}
