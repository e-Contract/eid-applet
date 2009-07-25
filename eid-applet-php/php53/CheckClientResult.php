<?php
    require_once('autoload.php');

    session_start();
    $config = $_SESSION['Configuration'];
?>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=windows-1252">
        <title>BEID PHP Chekc client Demo</title>
    </head>
    <body>
        <h1>BEID PHP Check client Demo</h1>
        <table>
            <tr><th>Java vendor</th>
                <td><?php echo $config->getJavaVendor(); ?></td>
            </tr>
            <tr><th>Java name</th>
                <td><?php echo $config->getJavaVersion(); ?></td>
            </tr>
            <tr><th>Navigator</th>
                <td><?php echo $config->getNavigatorUA(); ?></td>
            </tr>
            <tr><th>Readers</th>
                <td><?php echo $config->getEidReaders(); ?></td>
            </tr>
        </table>
    </body>
</html>
