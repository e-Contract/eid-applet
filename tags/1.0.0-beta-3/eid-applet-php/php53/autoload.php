<?php
/**
 * Autoloader
 *
 * @package BEIDApplet-PHP5
 * @author Bart Hanssens
 * @copyright 2009, Fedict
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt LGPL 3.0 license
 *
 * $Id$
 */

function __autoload($className) {
    if (!is_string($className)) {
        throw Exception('Autoloader: className must be string');
    }
    /* only alphanumeric and underscore are allowed */
    if (preg_match('/\W/', $className)) {
        throw Exception('Autoloader: illegal character in name');
    }

    /* get the "root folder" for the beid files */
    $base = dirname(__FILE__);

    $beidPart = DIRECTORY_SEPARATOR.'beid'.DIRECTORY_SEPARATOR;
    $inSub = strpos($base, $beidPart);
    if ($insub > 0) {
        $base = substr($base, 0, $inSub);
    }
    
    $subdirs = array(
        '',
        $beidPart.'dao',
        $beidPart.'helper',
        $beidPart.'message',
        $beidPart.'service');

    /** could be smarter */
    foreach ($subdirs as $sub) {
        $classFile = $base . $sub . DIRECTORY_SEPARATOR . $className . '.php';
        if (file_exists($classFile)) {
            require($classFile);
        }
    }
}        
?>
