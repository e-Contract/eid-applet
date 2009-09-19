<?php
/**
 * Helper class for various conversions
 *
 * @package BEIDApplet-PHP5
 * @author Bart Hanssens
 * @copyright 2009, Fedict
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt LGPL 3.0 license
 *
 * $Id$
 */

class BEIDHelperConvert {
    private static $monthNames = array(
        'JAN ' => 1,
        'FEB ' => 2, 'FEV ' => 2,
        'MAAR' => 3, 'MARS' => 3, 'MÄR ' => 3,
        'APR ' => 4, 'AVR ' => 4,
        'MEI ' => 5, 'MAI ' => 5,
        'JUN ' => 6, 'JUNI' => 6, 'JUIN' => 6,
        'JUL ' => 7, 'JULI' => 7, 'JUIL' => 7,
        'AUG ' => 8, 'AOUT' => 8,
        'SEP ' => 9, 'SEPT' => 9,
        'OCT ' => 10, 'OKT ' => 10,
        'NOV ' => 11,
        'DEC ' => 12, 'DEZ ' => 12
    );

    /**
     * Logs messages to error log (configurable in php.ini)
     *
     * @param string $message
     */
    private static function logger($message) {
       error_log($message);
    }

    /**
     * Unpack a byte to an integer
     *
     * @param string $byte byte to unpack
     * @return int
     */
    public static function byteAsInt($byte) {
        $arr = unpack('c', $byte);
        return (int) $arr[1];
    }

    /**
     * Unpack bytes to a string
     *
     * @param string $byte bytes to unpack
     * @return string
     */
    public static function bytesAsString($byte) {
        $arr = unpack('a*', $byte);
        return $arr[1];
    }

    /**
     * Unpack bytes to an hex string
     *
     * @param string $byte bytes to unpack
     * @return hexadecimal string
     */
    public static function bytesAsHexString($byte) {
        $arr = strtoupper(unpack('H*', $byte));
        return $arr[1];
    }

    /**
     * Unpack bytes to a DateTime, expecting input format 'DD MM YYYY'
     *
     * @param string $byte bytes to unpack
     * @return DateTime
     *
     * @todo use createFromFormat in PHP 5.3
     */
    public static function bytesAsDate($byte) {
        $arr = unpack('a*', $byte);
        /* len = 10 */

        $day = substr($arr[1], 0, 2);
        $month = substr($arr[1], 3, 2);
        $year = substr($arr[1], 6, 4);

        $date = new DateTime();
        $date->setDate($year, $month, $day);
        
        return $date;
    }
    

    /**
     * Unpack bytes to a DateTime, expecting input format 'DD MON YYYY'
     * 
     * @param string $byte bytes to unpack
     * @return DateTime
     */
    public static function bytesAsDateFromText($byte) {
        $arr = unpack('a*', $byte);

        /* createFromFormat in PHP 5.3 */

        $day = substr($arr[1], 0, 2);
        $monthName = substr($arr[1], 3, 4);
        $month = self::$monthNames[$monthName];
        $year = substr($arr[1], 8, 4);

        $date = new DateTime();
        $date->setDate($year, $month, $day);
        
        return $date;
    }

    /**
     * Convert raw certificate bytes to PEM
     *
     * @param string $cert certificate to convert
     * @return PEM string
     */
    public static function certToPEM($cert) {
        $begin = '-----BEGIN CERTIFICATE-----'."\n";
        $mid = chunk_split(base64_encode($cert), 64, "\n");
        $end = '-----END CERTIFICATE-----';

        $pem = $begin.$mid.$end;

        return $pem;
    }
}
?>
