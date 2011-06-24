<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<html>
<head>
<title>OWASP Secure Channel Binding Settings</title>
</head>
<body>
<h1>OWASP Secure Channel Binding Settings</h1>
<form method="post" action="channel-binding-config">
<p>Server Certificate (PEM-format):</p>
<textarea rows="10" cols="60" name="serverCertificate"></textarea>
<p><input type="submit" value="Change" /></p>
</form>
</body>
</html>