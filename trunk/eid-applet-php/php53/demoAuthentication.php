<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=windows-1252">
        <title>BEID PHP Authentication demo page</title>
        <script type="text/javascript" src="https://www.java.com/js/deployJava.js"></script>
    </head>
    <body>
        <h1>BEID PHP Authentication demo page</h1>

        <script type="text/javascript">
            var attributes = {
                code :'be.fedict.eid.applet.Applet.class',
                archive :'eid-applet.jar',
                width :600,
                height :300 };

            var parameters = {
                TargetPage :'AuthenticationResult.php',
                AppletService : 'AuthenticationService.php',
                BackgroundColor : '#ffffff',
                Language : 'en'
            };

            var version = '1.5';
            deployJava.runApplet(attributes, parameters, version);
     </script>
    </body>
</html>
