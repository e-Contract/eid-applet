<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<html>
<head>
<title>OWASP eID Applet Authentication Demo</title>
</head>
<body>
<h1>OWASP eID Applet Authentication Demo</h1>
<p>This demo shows the eID Applet running in authentication mode.</p>
<script src="https://www.java.com/js/deployJava.js"></script>
<script>
	var attributes = {
		code :'be.fedict.eid.applet.Applet.class',
		archive :'eid-applet-package-${pom.version}.jar',
		width :600,
		height :300
	};
	var parameters = {
		TargetPage :'authentication-result.jsp',
		AppletService :'owasp-authentication'
	};
	var version = '1.6';
	deployJava.runApplet(attributes, parameters, version);
</script>
</body>
</html>