<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<html>
<head>
<title>eID Applet Diagnostic Mode Test</title>
</head>
<body>
<h1>eID Applet Diagnostic Mode Test</h1>
<p>This page will test the eID Applet in Diagnostic Mode.</p>

<applet code="be.fedict.eid.applet.Applet.class" width="600"
	height="300" archive="eid-applet.jar" mayscript="true">
	<param name="TargetPage" value="javascript:diagnoseDone();" />
	<param name="AppletService" value="applet-diagnostic-service" />
	<param name="DiagnosticTestCallback" value="diagnosticTestCallback" />
</applet>

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