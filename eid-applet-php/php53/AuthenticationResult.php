<?php
    require_once('autoload.php');

    session_start();

    $identifier = $_SESSION['Identifier'];
?>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=windows-1252">
        <title>BEID PHP Authentication Demo</title>
    </head>
    <body>
        <h1>BEID PHP Authentication Demo</h1>
        <p><strong>Authentication Identifier: <?php echo $identifier; ?></strong></p>
    </body>
</html>
