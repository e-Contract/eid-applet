<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<html>
<head>
<title>OWASP eID Applet Identification Demo</title>
</head>
<body>
<h1>OWASP eID Applet Identification with Integrity Verification
Demo</h1>
<p>The page demonstrates the eID Applet running in Identification
mode. The eID Applet Service will also perform an integrity verification
on the received eID identity data.</p>
<script src="https://www.java.com/js/deployJava.js"></script>
<script>
	var attributes = {
		code :'be.fedict.eid.applet.Applet.class',
		archive :'eid-applet.jar',
		width :600,
		height :300,
		mayscript :'true'
	};
	var parameters = {
		TargetPage :'identification-integrity-result.jsp',
		AppletService :'owasp-identification-integrity'
	};
	var version = '1.6';
	deployJava.runApplet(attributes, parameters, version);
</script>
</body>
</html>