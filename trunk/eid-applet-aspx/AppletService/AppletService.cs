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

namespace Be.FedICT.EID.Applet.Service
{
	
	public class AppletService : IHttpHandler, IRequiresSessionState
	{
		
		public AppletService()
		{
		}
		
		public void ProcessRequest(HttpContext httpContext) {
			HttpRequest httpRequest = httpContext.Request;
			if ("GET".Equals(httpRequest.HttpMethod)) {
				HttpResponse httpResponse = httpContext.Response;
				httpResponse.Write("<html><body>The eID Applet Service should not be invoked directly.</body></html>");
				return;
			}
			if (!"POST".Equals(httpRequest.HttpMethod)) {
				HttpResponse httpResponse = httpContext.Response;
				httpResponse.StatusCode = 400; // bad request
				return;
			}
			String protocolVersion = httpRequest.Headers["X-AppletProtocol-Version"];
			if (!"1".Equals(protocolVersion)) {
				HttpResponse httpResponse = httpContext.Response;
				httpResponse.StatusCode = 400; // bad request
				return;
			}
			String messageType = httpRequest.Headers["X-AppletProtocol-Type"];
			if ("HelloMessage".Equals(messageType)) {
				HttpResponse httpResponse = httpContext.Response;
				httpResponse.AddHeader("X-AppletProtocol-Version", "1");
				httpResponse.AddHeader("X-AppletProtocol-Type", "IdentificationRequestMessage");
				return;
			} else if ("IdentityDataMessage".Equals(messageType)) {
				int identityFileSize = int.Parse(httpRequest.Headers["X-AppletProtocol-IdentityFileSize"]);
				Stream stream = httpRequest.InputStream;
				while (stream.Position < stream.Length) {
					int tag = stream.ReadByte();
					int length = stream.ReadByte();
					byte[] buffer = new byte[length];
					stream.Read(buffer, 0, length);
					if (7 == tag) {
						String name = Encoding.UTF8.GetString(buffer);
						httpContext.Session.Add("Identity.Name", name);
					} else if (8 == tag) {
						String firstName = Encoding.UTF8.GetString(buffer);
						httpContext.Session.Add("Identity.FirstName", firstName);
					}
				}
				HttpResponse httpResponse = httpContext.Response;
				httpResponse.AddHeader("X-AppletProtocol-Version", "1");
				httpResponse.AddHeader("X-AppletProtocol-Type", "FinishedMessage");
				return;
			} else {
				HttpResponse httpResponse = httpContext.Response;
				httpResponse.StatusCode = 400; // bad request
				return;
			}
		}
		
		public bool IsReusable {
			get {
				return true;
			}
		}
	}
}
