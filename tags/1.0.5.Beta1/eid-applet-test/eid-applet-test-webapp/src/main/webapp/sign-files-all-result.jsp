<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<html>
<head>
<title>eID Applet Files Signature Demo</title>
</head>
<body>
<h1>eID Applet Files Signature Demo</h1>
<p>Files signature created successfully.</p>
<p>Signature Value:</p>
<pre>
<%=session.getAttribute("SignatureValue")%>
</pre>
<p>Signed Files:</p>
<pre>
<%=session.getAttribute("signedFiles")%>
</pre>
<p>Signing Certificate Chain:</p>
<pre>
<%=session.getAttribute("SigningCertificateChain")%>
</pre>
<h2>Secure Client Environment Information</h2>
<table>
	<tr>
		<th>Attribute</th>
		<th>Value</th>
	</tr>
	<tr>
		<td>Client Java Version</td>
		<td><%=session.getAttribute("ClientJavaVersion")%></td>
	</tr>
	<tr>
		<td>Client Java Vendor</td>
		<td><%=session.getAttribute("ClientJavaVendor")%></td>
	</tr>
	<tr>
		<td>Client OS Name</td>
		<td><%=session.getAttribute("ClientOSName")%></td>
	</tr>
	<tr>
		<td>Client OS Architecture</td>
		<td><%=session.getAttribute("ClientOSArch")%></td>
	</tr>
	<tr>
		<td>Client OS Version</td>
		<td><%=session.getAttribute("ClientOSVersion")%></td>
	</tr>
	<tr>
		<td>Client Readers</td>
		<td><%=session.getAttribute("ClientReaders")%></td>
	</tr>
	<tr>
		<td>Client User Agent</td>
		<td><%=session.getAttribute("ClientUserAgent")%></td>
	</tr>
	<tr>
		<td>Client Navigator User Agent</td>
		<td><%=session.getAttribute("ClientNavigatorUserAgent")%></td>
	</tr>
	<tr>
		<td>Client Navigator App Name</td>
		<td><%=session.getAttribute("ClientNavigatorAppName")%></td>
	</tr>
	<tr>
		<td>Client Navigator App Version</td>
		<td><%=session.getAttribute("ClientNavigatorAppVersion")%></td>
	</tr>
	<tr>
		<td>Client SSL Cipher Suite</td>
		<td><%=session.getAttribute("ClientSslCipherSuite")%></td>
	</tr>
	<tr>
		<td>Client SSL Key Size</td>
		<td><%=session.getAttribute("ClientSslKeySize")%></td>
	</tr>
	<tr>
		<td>Client Remote Address</td>
		<td><%=session.getAttribute("ClientRemoteAddress")%></td>
	</tr>
</table>
<p><a href="sign-files-all.jsp">Again</a> | <a href=".">Main Page</a></p>
</body>
</html>