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
using System.Text;


namespace Be.FedICT.EID.Applet.Service {
	
	public class AuthnAppletService : IHttpHandler, IRequiresSessionState {
		
		public const string IDENTIFIER_SESSION_KEY = "Identifier";
		
		public const string CHALLENGE_SESSION_KEY = "Challenge";
		
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
				httpContext.Session.Remove(IDENTIFIER_SESSION_KEY);
				
				sendCommand("AuthenticationRequestMessage", httpResponse);
				Random random = new Random();
				byte[] challenge = new byte[20];
				random.NextBytes(challenge);
				httpResponse.BinaryWrite(challenge);
				
				httpContext.Session.Add(CHALLENGE_SESSION_KEY, challenge);
				return;
			}
			if ("AuthenticationDataMessage".Equals(messageType)) {
				// parse arguments
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
				Log("certs data size: " + certsData.Length);
				Log("cert data size: " + certificate2.GetRawCertData().Length);
				
				// verify signature
				MemoryStream memoryStream = new MemoryStream();
				memoryStream.Write(saltValue, 0, saltValue.Length);
				UTF8Encoding utf8Encoding = new UTF8Encoding();
				byte[] legalNotice = utf8Encoding.GetBytes("Declaration of authentication intension.\n"
					+ "The following data should be interpreted as an authentication challenge.\n");
				memoryStream.Write(legalNotice, 0, legalNotice.Length);
				byte[] challenge = (byte[]) httpContext.Session[CHALLENGE_SESSION_KEY];
				memoryStream.Write(challenge, 0, challenge.Length);
				httpContext.Session.Remove(CHALLENGE_SESSION_KEY);
				memoryStream.Seek(0, SeekOrigin.Begin);
				byte[] toBeSignedData = new byte[memoryStream.Length];
				memoryStream.Read(toBeSignedData, 0, toBeSignedData.Length);
				
				RSACryptoServiceProvider rsaCryptoService = (RSACryptoServiceProvider)certificate2.PublicKey.Key;
				
				Log("to be signed data size: " + toBeSignedData.Length);
				Log("signature value size: " + signatureValue.Length);
				
				bool signatureResult;
				try {
					signatureResult = rsaCryptoService.VerifyData(toBeSignedData, new SHA1CryptoServiceProvider(), signatureValue);
					Log("signature result: " + signatureResult);
				}
				catch(Exception e) {
					Log("error: " + e.Message);
					httpResponse.StatusCode = 400; // bad request
					return;
				}
				if (false == signatureResult) {
					httpResponse.StatusCode = 400; // bad request
					return;
				}
				
				// TODO: verify certificate validity
				
				X500DistinguishedName subjectName = certificate2.SubjectName;
				Log("subject: " + subjectName.Name);
				
				int commaIdx = subjectName.Name.IndexOf(",");
				int prefixSize = "OID.2.5.4.5=".Length;
				string identifier = subjectName.Name.Substring(prefixSize, commaIdx - prefixSize);
				httpContext.Session.Add(IDENTIFIER_SESSION_KEY, identifier);
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
