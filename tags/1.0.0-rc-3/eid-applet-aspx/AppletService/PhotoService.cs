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
	
	
	public class PhotoService : IHttpHandler, IRequiresSessionState {
		
		public PhotoService() {
		}
		
		public void ProcessRequest(HttpContext httpContext) {
			HttpResponse httpResponse = httpContext.Response;
			httpResponse.ContentType = "image/jpg";
			httpResponse.AddHeader("Cache-Control", "no-cache, no-store, must-revalidate, max-age=-1");
			httpResponse.AddHeader("Pragma", "no-cache, no-store");
			httpResponse.AddHeader("Expires", "-1");
			
			byte[] photo = (byte[]) httpContext.Session["Identity.Photo"];
			Stream output = httpResponse.OutputStream;
			output.Write(photo, 0, photo.Length);
			
			httpResponse.Flush();
		}
		
		public bool IsReusable {
			get {
				return true;
			}
		}
	}
}
