<?php
/**
 * Check client service
 *
 * @package BEIDApplet-PHP5
 * @author Bart Hanssens
 * @copyright 2009, Fedict
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt LGPL 3.0 license
 *
 * $Id$
 */

require_once('autoload.php');

session_start();

$service = new BEIDServiceCheckClient();
$service->processRequest();

?>