ASP.NET eID Applet Service
==========================

=== 1. Introduction

The artifact holds the source code for the ASP.NET implementation of the
eID Applet Service server-side component. The implementation is based on a
IHttpHandler component.
We're using Linux as development platform though the code should also run
on the Microsoft Windows platforms.
We're using MonoDevelop as development environment for the ASP.NET code.
The ASP.NET DLL can be tested using xsp2 (Mono).
MonoDevelop is available from:
	http://monodevelop.com/
Developers can use SharpDevelop 2.2 on the Windows platform.
SharpDevelop is available from:
	http://www.icsharpcode.net/


=== 2. Usage

First compile the DLL using MonoDevelop. Copy the AppletService.dll to the
bin directory of your ASP.NET web application.
Configure the AppletService HTTP handler via your web.config file:
<configuration xmlns="http://schemas.microsoft.com/.NetConfiguration/v2.0">
	<system.web>
		<httpHandlers>
			<add path="/applet-service" verb="*"
	type="Be.FedICT.EID.Applet.Service.AppletService, AppletService"
	validate="True"/>
    		</httpHandlers>
	</system.web>
</configuration>

Configure the AuthnAppletService HTTP handler via your web.config file:
<configuration
xmlns="http://schemas.microsoft.com/.NetConfiguration/v2.0">
<system.web>
    <httpHandlers>
       <add path="/applet-authn-service" verb="*"
type="Be.FedICT.EID.Applet.Service.AuthnAppletService, AppletService"
validate="True"/>
    </httpHandlers>
</system.web>
</configuration>


=== 3. ASP.NET runtime

Mono comes with an ASP.NET runtime program named xsp2. Here we'll describe
how to configure xsp2.

Generate an RSA keypair and self-signed certificate via:
	openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout private-key.der -out cert.crt

Create a PKCS#12 keystore via:
	openssl pkcs12 -export -out keystore.p12 -inkey private-key.der -in cert.crt

Start the ASP.NET web service via (Mono):
	xsp2 --https --port 8443 --p12file keystore.p12 --pkpwd secret
--verbose

Test by browsing to:
	https://localhost:8443

Create some index.aspx file in the directory where you launched xsp2.
