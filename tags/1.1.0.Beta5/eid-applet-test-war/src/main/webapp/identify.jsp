<html>
<head>
<title>eID Applet Identification Demo</title>
</head>
<body>
	<h1>eID Applet Identification Demo</h1>
	<script src="https://www.java.com/js/deployJava.js"></script>
	<script>
		var attributes = {
			code : 'be.fedict.eid.applet.Applet.class',
			archive : 'eid-applet-package-${pom.version}.jar',
			width : 600,
			height : 300
		};
		var parameters = {
			TargetPage : 'result.jsp',
			AppletService : 'applet-service;jsessionid=<%=session.getId()%> ',
			BackgroundColor : '#ffffff',
			Language : 'en'
		};
		var version = '1.6';
		deployJava.runApplet(attributes, parameters, version);
	</script>
</body>
</html>