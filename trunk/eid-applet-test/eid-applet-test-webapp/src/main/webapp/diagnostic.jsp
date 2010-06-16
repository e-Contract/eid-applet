<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<html>
<head>
<title>eID Applet Diagnostic Mode Test</title>
</head>
<body>
<h1>eID Applet Diagnostic Mode Test</h1>
<p>This page will test the eID Applet in Diagnostic Mode.</p>
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
		AppletService :'applet-diagnostic-service',
		DiagnosticTestCallback :'diagnosticTestCallback',
		TargetPage : 'javascript:diagnoseDone();'
	};
	var version = '1.6';
	deployJava.runApplet(attributes, parameters, version);
</script>
<script>
	function diagnosticTestCallback(testId, testDescription, testResult, testResultDescription) {
		document.getElementById('testResults').innerHTML += '<tr>' + 
			'<td>' + testId + '</td>' + 
			'<td>' + testDescription + '</td>' + 
			'<td>' + testResult + '</td>' + 
			'<td>' + testResultDescription + '</td>' +
			'</tr>';
	}
	function diagnoseDone() {
		document.getElementById('message').innerHTML = 'End of diagnose.';
	}
</script>
<table id="testResults">
	<tr>
		<th>Test ID</th>
		<th>Test Description</th>
		<th>Successful</th>
		<th>Information</th>
	</tr>
</table>
<pre id="message"></pre>
</body>
</html>