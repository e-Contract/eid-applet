<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@page import="be.fedict.eid.applet.service.Identity"%>
<%@page import="be.fedict.eid.applet.service.Address"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Authentication Result Page</title>
</head>
<body>
<h1>Authentication Result Page</h1>
<p>Authenticated User Identifier: <%=session.getAttribute("eid.identifier")%>
</p>
<p>Authentication Certificate Chain:</p>
<pre>
<%=session.getAttribute("AuthenticationCertificateChain")%>
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
<a href="authn-secure-client.jsp">Again</a>
|
<a href=".">Main Page</a>
</body>
</html>