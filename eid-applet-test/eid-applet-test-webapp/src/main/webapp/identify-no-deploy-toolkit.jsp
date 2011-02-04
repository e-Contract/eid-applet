<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<html>
<head>
<title>eID Applet Identification Demo</title>
</head>
<body>
<h1>eID Applet Identification Demo</h1>
<p>This test is not using the Deployment Toolkit JavaScript of Java
6u10.</p>
<applet code="be.fedict.eid.applet.Applet.class" width="600"
	height="300" archive="eid-applet-package-${pom.version}.jar">
	<param name="TargetPage" value="identity-result.jsp" />
	<param name="AppletService" value="applet-service" />
</applet>
</body>
</html>