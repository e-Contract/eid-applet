ASP.NET eID Applet Service
==========================

=== 1. Introduction

The artifact holds the source code for the ASP.NET implementation of the
eID Applet Service server-side component. The implementation is based on a
IHttpHandler component.
We're using Linux as development platform though the code should also run
on the Microsoft Windows platforms.
We're using MonoDevelop as development environment for the ASP.NET code.
The ASP.NET DLL can be tested using xsp2.


=== 2. Usage

Configure the AppletService HTTP handler via you web.config file:
<?xml version="1.0"?>
<configuration xmlns="http://schemas.microsoft.com/.NetConfiguration/v2.0">
	<system.web>
		<httpHandlers>
			<add path="/applet-service" verb="*"
	type="Be.FedICT.EID.Applet.Service.AppletService, AppletService"
	validate="True"/>
    		</httpHandlers>
	</system.web>
</configuration>


=== 3. ASP.NET runtime

Generate an RSA keypair and self-signed certificate via:
	openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout private-key.der -out cert.crt

Create a PKCS#12 keystore via:
	openssl pkcs12 -export -out keystore.p12 -inkey private-key.der -in cert.crt

Start the ASP.NET web service via:
	xsp2 --https --port 8443 --p12file keystore.p12 --pkpwd secret
--verbose

Test by browsing to:
	https://localhost:8443

Create some index.aspx file in the directory where you launched xsp2.
