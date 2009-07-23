<?php
/**
 * Description of BEIDHelperTLV
 *
 * @package BEIDApplet
 * @author Bart Hanssens
 * @copyright 2009, Fedict
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt LGPL 3.0 license
 *
 * $Id$
 */


class BEIDHelperTLV {
    private $tag;
    private $length;
    private $value;

    /**
     * Get the tag number
     * 
     * @return int
     */
    public function getTag() {
        return $this->tag;
    }
    /**
     * Set the tag
     *
     * @param int tag
     */
    public function setTag($tag) {
        $this->tag = $tag;
    }
    /**
     * Get the length of the value
     *
     * @return int length
     */
    public function getLength() {
        return $this->length;
    }
    /**
     * Set the length of the value
     * @param int $length
     */
    public function setLength($length) {
        if ($length < 0) {
            throw new BEIDHelperException("TLV: Invalid length");
        }
        $this->length = $length;
    }

    /**
     * Get the value
     *
     * @return string
     */
    public function getValue() {
        return $this->value;
    }
    /**
     * Set the value
     *
     * @param string $value
     */
    public function setValue($value) {
        $this->value = $value;
    }


    /**
     * Create a TLV object from tag-length-value
     *
     * @param int $tag tag number
     * @param int $length length of the value
     * @param string $value the value itself
     * @return BEIDHelperTLV
     */
    public static function createFromTLV($tag, $length, $value) {
        $tlv = new BEIDHelperTLV();

        $tlv->setTag($tag);
        $tlv->setLength($length);
        $tlv->setValue($value);

        return $tlv;
    }

    /**
     * Create a TLV from an input stream
     *
     * @param resource $stream input stream
     * @return BEIDHelperTLV
     */
    public static function createFromStream($stream) {
        $tlv = new BEIDHelperTLV();

        $tag = BEIDHelperConvert::byteAsInt(stream_get_contents($stream, 1));
        if ($tag) {
            $tlv->setTag($tag);
        } else {
            BEIDHelperLogger::logger('TLV: tag 0');
            return $tlv;
        }

        $length = BEIDHelperConvert::byteAsInt(stream_get_contents($stream, 1));
        if ($length) {
            $tlv->setLength($length);
         } else {
            BEIDHelperLogger::logger('TLV: no length for tag '.$tag);
           // throw new Exception('TLV: Could not read length for tag '.$tag, 3);
        }

        $value = stream_get_contents($stream, $length);
        if ($value) {
            $tlv->setValue($value);
         } else {
            BEIDHelperLogger::logger('TLV: no value for tag '.$tag);
         }
        return $tlv;
    }

    public static function getValueFromStream($stream, $expectedTag) {
        $tlv = $this->createFromStream($stream);
        if ($tlv->getTag() != $expectedTag) {
            throw new BEIDHelperException('TLV expected '.$expectedTag.', not '.$tlv->getTag());
        }
        return $tlv->getValue();
    }
}
?>
