<?php
/**
 * Citizen's (home) address class
 *
 * @package BEIDApplet-PHP5
 * @author Bart Hanssens
 * @copyright 2009, Fedict
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt LGPL 3.0 license
 *
 * $Id$
 */

class BEIDAddress {
    private $streetAndNumber;
    private $zip;
    private $municipality;

    const STREET_NUMBER = 1;
    const ZIP = 2;
    const MUNICIPALITY = 3;

    /**
     * Get street and number (they are in the same field on the eID card)
     *
     * @return string
     */
    public function getStreetAndNumber() {
        return $this->streetAndNumber;
    }
    /**
     * Set street and number
     *
     * @param string $streetNumber street and number
     */
    public function setStreetAndNumber($streetNumber) {
        $this->streetAndNumber = $streetNumber;
    }

    /**
     * Get the ZIP-code of the municipality, in Belgium this is a 4 digit string
     *
     * @return string
     */
    public function getZip() {
        return $this->zip;
    }
    /**
     * Set the ZIP-code of the municipality
     *
     * @param string $zip ZIP code
     */
    public function setZip($zip) {
        $this->zip = $zip;
    }

    /**
     * Get the name of the municipality
     *
     * @return string
     */
    public function getMunicipality() {
        return $this->municipality;
    }
    /**
     * Set the name of the municipality
     *
     * @param string $municipality
     */
    public function setMunicipality($municipality) {
        if (! is_string($municipality)) {
            throw new BEIDAddressException('Municipality must be a string');
        }
        $this->municipality = $municipality;
    }

    /**
     * "Magic" PHP convenience method
     *
     * @return string
     */
    public function __toString() {
        return "$this->streetAndNumber, $this->zip $this->municipality";
    }

}
?>
