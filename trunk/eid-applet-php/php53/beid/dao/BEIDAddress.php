<?php
/**
 * Home address class
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
    
    public function getStreetAndNumber() {
        return $this->streetAndNumber;
    }
    public function setStreetAndNumber($streetNumber) {
        $this->streetAndNumber = $streetNumber;
    }

    public function getZip() {
        return $this->zip;
    }
    public function setZip($zip) {
        $this->zip = $zip;
    }

    public function getMunicipality() {
        return $this->municipality;
    }
    public function setMunicipality($municipality) {
        $this->municipality = $municipality;
    }

    public function __toString() {
        return $this->streetAndNumber .', '. $this->zip .' '. $this->municipality;
    }

}
?>
