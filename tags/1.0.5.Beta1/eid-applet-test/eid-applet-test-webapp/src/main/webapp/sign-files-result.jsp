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
<p><a href="sign-files.jsp">Again</a> | <a href=".">Main Page</a></p>
</body>
</html>