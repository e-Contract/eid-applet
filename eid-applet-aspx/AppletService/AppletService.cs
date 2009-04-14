// MyClass.cs created with MonoDevelop
// User: fcorneli at 2:13 PM 4/14/2009
//
// To change standard headers go to Edit->Preferences->Coding->Standard Headers
//

using System;
using System.Web;

namespace Be.FedICT.EID.Applet.Service
{
	
	
	public class AppletService : IHttpHandler
	{
		
		public AppletService()
		{
		}
		
		public void ProcessRequest(HttpContext context) {
		}
		
		public bool IsReusable {
			get {
				return true;
			}
		}
	}
}
