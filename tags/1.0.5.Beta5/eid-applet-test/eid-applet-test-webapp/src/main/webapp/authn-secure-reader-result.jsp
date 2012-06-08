<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@page import="be.fedict.eid.applet.service.Identity"%>
<%@page import="be.fedict.eid.applet.service.Address"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Authentication Result Page (requires a secure smart card reader)</title>
</head>
<body>
<h1>Authentication Result Page (requires a secure smart card reader)</h1>
<p>Authenticated User Identifier: <%=session.getAttribute("eid.identifier")%>
</p>
<p>Authentication Certificate Chain:</p>
<pre>
<%=session.getAttribute("AuthenticationCertificateChain")%>
</pre>
<a href="authenticate-secure-reader.jsp">Again</a>
|
<a href=".">Main Page</a>
</body>
</html>