// https://www.java.com/js/deployJava.js
// readable version: http://java.com/js/deployJava.txt
var deployJavaEIDApplet = {
	runApplet : function(attributes, parameters) {
		// fix for Mac OS X 64 bit
		var javaArgs = '';
		if (navigator.userAgent.indexOf('Mac OS X 10_6') != -1
				|| navigator.userAgent.indexOf('Mac OS X 10.6') != -1) {
			javaArgs += '-d32';
		}
		parameters.java_arguments = javaArgs;
		// fix for IE 7/8
		var version = '1.6';
		var browser = deployJava.getBrowser();
		if (browser == 'MSIE') {
			version = '1.6.0_27';
		}
		deployJava.runApplet(attributes, parameters, version);
	}
};