<?php
    require_once('autoload.php');

    session_start();
    $identity = $_SESSION['Identity'];
?>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=windows-1252">
        <title>BEID PHP Identity Demo</title>
    </head>
    <body>
        <h1>BEID PHP Identity Demo</h1>
        <table>
            <tr><th>First Name</th>
                <td><?php echo $identity->getFirstName(); ?></td>
            </tr>
            <tr><th>Family Name</th>
                <td><?php echo $identity->getName(); ?></td>
            </tr>
            <tr><th>Street</th>
                <td><?php echo $identity->getAddress()->getStreetAndNumber(); ?></td>
            </tr>
            <tr><th>City</th>
                <td><?php echo $identity->getAddress()->getMunicipality(); ?></td>
            </tr>
        </table>
    </body>
</html>
