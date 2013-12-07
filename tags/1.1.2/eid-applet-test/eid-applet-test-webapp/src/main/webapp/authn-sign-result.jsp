<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@page import="be.fedict.eid.applet.service.Identity"%>
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
<p>
Authentication signature value: <%=session.getAttribute("AuthenticationSignatureValue")%>
</p>
<h2>Certificates</h2>
Authentication Certificate:
<pre>
<%=session.getAttribute("eid.certs.authn")%>
</pre>
Signature Certificate:
<pre>
<%=session.getAttribute("eid.certs.sign")%>
</pre>
Citizen CA Certificate:
<pre>
<%=session.getAttribute("eid.certs.ca")%>
</pre>
Root CA Certificate:
<pre>
<%=session.getAttribute("eid.certs.root")%>
</pre>
<a href="authn-sign.jsp">Again</a>
|
<a href=".">Main Page</a>
</body>
</html>