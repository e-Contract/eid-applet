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
using System.Text;
using System.Reflection;

namespace Be.FedICT.EID.Applet.Service {
	
	public class AppletService : IHttpHandler, IRequiresSessionState {
		
		public AppletService() {
		}
		
		public void ProcessRequest(HttpContext httpContext) {
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
				sendCommand("IdentificationRequestMessage", httpResponse);
				return;
			} else if ("IdentityDataMessage".Equals(messageType)) {
				int identityFileSize = int.Parse(httpRequest.Headers["X-AppletProtocol-IdentityFileSize"]);
				Stream stream = httpRequest.InputStream;
				Identity identity = new Identity();
				Type identityType = typeof(Identity);
				PropertyInfo[] properties = identityType.GetProperties();
				while (stream.Position < stream.Length) {
					int tag = stream.ReadByte();
					int length = stream.ReadByte();
					byte[] buffer = new byte[length];
					stream.Read(buffer, 0, length);
					switch(tag) {
					case 7:
						String name = Encoding.UTF8.GetString(buffer);
						httpContext.Session.Add("Identity.Name", name);
						break;
					case 8:
						String firstName = Encoding.UTF8.GetString(buffer);
						httpContext.Session.Add("Identity.FirstName", firstName);
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
