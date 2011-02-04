<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<c:set var="signDigestAlgo" scope="session"
	value="${param.signDigestAlgo}" />
<c:set var="filesDigestAlgo" scope="session"
	value="${param.filesDigestAlgo}" />
<html>
<head>
<title>eID Applet Files Signature Test</title>
</head>
<body>
<h1>eID Applet Files Signature Test</h1>
<script src="https://www.java.com/js/deployJava.js"></script>
<script>
	var attributes = {
		code :'be.fedict.eid.applet.Applet.class',
		archive :'eid-applet-package-${pom.version}.jar',
		width :600,
		height :300
	};
	var parameters = {
		TargetPage :'sign-files-result.jsp',
		AppletService :'applet-service-sign-files',
		BackgroundColor :'#ffffff',
		Language :'en'
	};
	var version = '1.5';
	deployJava.runApplet(attributes, parameters, version);
</script>
</body>
</html>