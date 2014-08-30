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
<p>Signature Valid: <%=session.getAttribute("SignatureValid")%></p>
<p>Signing Certificate Chain:</p>
<pre>
<%=session.getAttribute("SigningCertificateChain")%>
</pre>
<p><a href="sign-text.jsp">Again</a> | <a href=".">Main Page</a></p>
</body>
</html>