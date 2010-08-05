<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<html>
<head>
<title>eID Applet Kiosk Mode Test</title>
</head>
<body>
<h1>eID Applet Kiosk Mode Test</h1>
<p>This page will test the eID Applet in Kiosk Mode. After removing
your eID card, a Javascript pop-up should appear.</p>
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
		AppletService :'applet-kiosk-service',
		RemoveCardCallback :'removeCardCallback'
	};
	var version = '1.6';
	deployJava.runApplet(attributes, parameters, version);
</script>
<script>
	function removeCardCallback() {
		alert('eID card removal has been detected by the web page.');
	}
</script>
<p><a href="kiosk.jsp">Again</a> | <a href=".">Main Page</a></p>
</body>
</html>