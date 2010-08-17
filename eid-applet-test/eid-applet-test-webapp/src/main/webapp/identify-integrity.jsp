<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<html>
<head>
<title>eID Applet Identification Demo</title>
</head>
<body>
<h1>eID Applet Identification Demo</h1>
<script src="https://www.java.com/js/deployJava.js"></script>
<script>
	var attributes = {
		code :'be.fedict.eid.applet.Applet.class',
		archive :'eid-applet.jar',
		width :600,
		height :300
	};
	var parameters = {
		TargetPage :'identity-integrity-result.jsp',
		AppletService :'applet-service-integrity',
		BackgroundColor :'#ffffff',
		Language : 'fr',
		HideDetailsButton : 'true'
	};
	var version = '1.6';
	deployJava.runApplet(attributes, parameters, version);
</script>
</body>
</html>