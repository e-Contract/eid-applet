<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<html>
<head>
<title>eID Applet Signature Demo</title>
</head>
<body>
<h1>eID Applet Signature Demo</h1>
<p>Signature created successfully.</p>
<p>Signature Value:</p>
<pre>
<%=session.getAttribute("SignatureValue")%>
</pre>
<p>Signing Certificate Chain:</p>
<pre>
<%=session.getAttribute("SigningCertificateChain")%>
</pre>
<h2>Signature Identity (retrieved during pre-sign phase)</h2>
<table>
	<tr>
		<th>Name</th>
		<th>Value</th>
	</tr>
	<tr>
		<td>name</td>
		<td><%=session.getAttribute("IdentityName")%></td>
	</tr>
	<tr>
		<td>city</td>
		<td><%=session.getAttribute("IdentityCity")%></td>
	</tr>
</table>
<p><a href="sign-identity.jsp">Again</a> | <a href=".">Main Page</a></p>
</body>
</html>