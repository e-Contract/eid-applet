<?php
/**
 * Logger helper class
 *
 * @package BEIDApplet-PHP5
 * @author Bart Hanssens
 * @copyright 2009, Fedict
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt LGPL 3.0 license
 *
 * $Id$
 */
 
class BEIDHelperLogger {
    /**
     * Logs messages to error log (configurable in php.ini)
     *
     * @param string $message
     */
    public static function logger($message) {
       error_log($message);
    }
}
?>
