<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<html>
<head>
<title>eID Applet Identification Demo</title>
<style type="text/css">
h1 {
	color: white;
}
</style>
</head>
<body bgcolor="#000000">
<h1>eID Applet Identification Demo</h1>
<script src="https://www.java.com/js/deployJava.js"></script>
<script>
	var attributes = {
		code :'be.fedict.eid.applet.Applet.class',
		archive :'eid-applet-package-${pom.version}.jar',
		width :600,
		height :300
	};
	var parameters = {
		TargetPage :'authn-remove-card-result.jsp',
		AppletService :'applet-service-authn-remove-card',
		BackgroundColor :'#000000',
		ForegroundColor : '#ffffff',
		Language : 'fr'
	};
	var version = '1.5';
	deployJava.runApplet(attributes, parameters, version);
</script>
</body>
</html>