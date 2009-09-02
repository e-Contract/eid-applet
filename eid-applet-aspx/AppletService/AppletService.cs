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
using System.Web.Configuration;
using System.IO;
using System.Text;
using System.Reflection;

namespace Be.FedICT.EID.Applet.Service {
	
	public class AppletService : IHttpHandler, IRequiresSessionState {
		
		public AppletService() {
		}
		
		private void Log(string message) {
			System.Console.WriteLine(message);
		}
		
		public void ProcessRequest(HttpContext httpContext) {
			Log("process request");
			
			//WebConfigurationManager.
			//object T = WebConfigurationManager.GetWebApplicationSection("httpHandlers") ;
    		//Log("config available: " + (T != null));
			
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
				httpResponse.AddHeader("X-AppletProtocol-IncludeAddress", "true");
				sendCommand("IdentificationRequestMessage", httpResponse);
				return;
			} else if ("IdentityDataMessage".Equals(messageType)) {
				int identityFileSize = int.Parse(httpRequest.Headers["X-AppletProtocol-IdentityFileSize"]);
				Stream stream = httpRequest.InputStream;
				byte[] identityFile = new byte[identityFileSize];
				stream.Read(identityFile, 0, identityFileSize);
				Identity identity = new Identity();
				Type identityType = typeof(Identity);
				PropertyInfo[] properties = identityType.GetProperties();
				int idx = 0;
				while (idx < identityFileSize) {
					int tag = identityFile[idx++];
					int length = identityFile[idx++];
					byte[] buffer = new byte[length];
					Array.Copy(identityFile, idx, buffer, 0, length);
					idx += length;
					switch(tag) {
					case 6:
						String nationalNumber = Encoding.UTF8.GetString(buffer);
						httpContext.Session.Add("Identity.NationalNumber", nationalNumber);
						break;
					case 7:
						String name = Encoding.UTF8.GetString(buffer);
						httpContext.Session.Add("Identity.Name", name);
						break;
					case 8:
						String firstName = Encoding.UTF8.GetString(buffer);
						httpContext.Session.Add("Identity.FirstName", firstName);
						break;
					case 12:
						String dateOfBirth = Encoding.UTF8.GetString(buffer);
						httpContext.Session.Add("Identity.DateOfBirth", dateOfBirth);
						break;
					case 13:
						String gender = Encoding.UTF8.GetString(buffer);
						httpContext.Session.Add("Identity.Gender", gender);
						break;
					}
					foreach (PropertyInfo property in properties) {
						object[] tlvFieldAttributes = property.GetCustomAttributes(typeof(TlvField), false);
						if (0 == tlvFieldAttributes.Length) {
							continue;
						}
						TlvField tlvFieldAttribute = (TlvField) tlvFieldAttributes[0];
						int tlvTag = tlvFieldAttribute.Tag;
						if (tlvTag == tag) {
							String fieldValue = Encoding.UTF8.GetString(buffer);
							property.SetValue(identity, fieldValue, null);
						}
					}
					httpContext.Session.Add("Identity", identity);
				}
				
				int addressFileSize = int.Parse(httpRequest.Headers["X-AppletProtocol-AddressFileSize"]);
				byte[] addressFile = new byte[addressFileSize];
				stream.Read(addressFile, 0, addressFileSize);
				idx = 0;
				while (idx < addressFileSize - 1) {
					int tag = addressFile[idx++];
					int length = addressFile[idx++];
					byte[] buffer = new byte[length];
					Array.Copy(addressFile, idx, buffer, 0, length);
					idx += length;
					switch(tag) {
					case 1:
						String streetAndNumber = Encoding.UTF8.GetString(buffer);
						httpContext.Session.Add("Address.StreetAndNumber", streetAndNumber);
						break;
					case 2:
						String zip = Encoding.UTF8.GetString(buffer);
						httpContext.Session.Add("Address.ZIP", zip);
						break;
					case 3:
						String municipality = Encoding.UTF8.GetString(buffer);
						httpContext.Session.Add("Address.Municipality", municipality);
						break;
					}
				}
				sendCommand("FinishedMessage", httpResponse);
				return;
			} else {
				httpResponse.StatusCode = 400; // bad request
				return;
			}
		}
		
		public bool IsReusable {
			get {
				return true;
			}
		}
		
		private void sendCommand(string command, HttpResponse httpResponse) {
			httpResponse.AddHeader("X-AppletProtocol-Version", "1");
			httpResponse.AddHeader("X-AppletProtocol-Type", command);
		}
	}
}
