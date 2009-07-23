<?php

require_once('autoload.php');

session_start();

$service = new BEIDServiceIdentity();
$service->processRequest();

?>