<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<c:set var="toBeSigned" scope="session" value="${param.toBeSigned}" />
<c:set var="digestAlgo" scope="session" value="${param.digestAlgo}" />
<html>
<head>
<title>eID Applet Signature Test</title>
</head>
<body>
<h1>eID Applet Signature Test</h1>
<script src="https://www.java.com/js/deployJava.js"></script>
<script>
	var attributes = {
		code :'be.fedict.eid.applet.Applet.class',
		archive :'eid-applet-package-${pom.version}.jar',
		width :600,
		height :300
	};
	var parameters = {
		TargetPage :'sign-result.jsp',
		AppletService :'applet-service-sign',
		BackgroundColor :'#ffffff',
		Language :'en'
	};
	var version = '1.5';
	deployJava.runApplet(attributes, parameters, version);
</script>
</body>
</html>