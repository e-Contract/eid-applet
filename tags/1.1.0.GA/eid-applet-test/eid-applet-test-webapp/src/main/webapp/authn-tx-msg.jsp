<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<html>
<head>
<title>eID Applet Authentication Demo</title>
</head>
<body>
	<h1>eID Applet Authentication Demo</h1>
	<p>Here we demonstrate an eID authentication that also signs a
		human-readable transaction message. On the new eID aware secure pinpad
		readers the transaction message is displayed on the reader itself.</p>
	<script src="https://www.java.com/js/deployJava.js"></script>
	<script>
		var attributes = {
			code : 'be.fedict.eid.applet.Applet.class',
			archive : 'eid-applet-package-${pom.version}.jar',
			width : 600,
			height : 300
		};
		var parameters = {
			TargetPage : 'authn-tx-msg-result.jsp',
			AppletService : 'applet-service-authn-tx-msg'
		};
		var version = '1.6';
		deployJava.runApplet(attributes, parameters, version);
	</script>
</body>
</html>