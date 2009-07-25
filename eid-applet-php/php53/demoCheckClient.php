<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=windows-1252">
        <title>BEID PHP Check client demo</title>
        <script type="text/javascript" src="https://www.java.com/js/deployJava.js"></script>
    </head>
    <body>
        <h1>BEID PHP Check client demo</h1>

        <script type="text/javascript">
            var attributes = {
                code :'be.fedict.eid.applet.Applet.class',
                archive :'eid-applet.jar',
                width :400, height :300 };

            var parameters = {
                TargetPage :'CheckClientResult.php',
                AppletService : 'CheckClientService.php',
                BackgroundColor : '#ffffff',
                NavigatorUserAgent : navigator.userAgent,
                NavigatorAppName : navigator.appName,
                NavigatorAppVersion : navigator.appVersion
            };

            var version = '1.6';
            deployJava.runApplet(attributes, parameters, version);
     </script>
    </body>
</html>
