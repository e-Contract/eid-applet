<?php
/**
 * Client environment (applet)
 *
 * @package BEIDApplet-PHP5
 * @author Bart Hanssens
 * @copyright 2009, Fedict
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt LGPL 3.0 license
 *
 * $Id$
 */

class BEIDClientEnvironment {
    private $javaVendor;
    private $javaVersion;

    private $osName;
    private $osVersion;
    private $osArch;

    private $navigatorUA;
    private $navigatorName;
    private $navigatorVersion;

    private $readers;

    /**
     * Get the name of the java vendor
     *
     * @return string
     */
    public function getJavaVendor() {
        return $this->javaVendor;
    }
    /**
     * Set the name of the java vendor
     *
     * @param string $javaVendor
     */
    public function setJavaVendor($javaVendor) {
        if (! is_string($javaVendor)) {
            throw new BEIDClientEnvironmentException('Java vendor must be a string');
        }
        $this->javaVendor = $javaVendor;
    }

    /**
     * Get the java version string
     *
     * @return string
     */
    public function getJavaVersion() {
        return $this->javaVersion;
    }
    /**
     * Set the java version
     *
     * @param string $javaVersion
     */
    public function setJavaVersion($javaVersion) {
        if (! is_string($javaVersion)) {
            throw new BEIDClientEnvironmentException('Java version must be a string');
        }
        $this->javaVersion = $javaVersion;
    }

    /**
     * Get the navigator (browser) user agent string
     *
     * @return string
     */
    public function getNavigatorUA() {
        return $this->navigatorUA;
    }
    /**
     * Set the navigator string
     *
     * @param string $navigatorUA
     */
    public function setNavigatorUA($navigatorUA) {
        if (! is_string($navigatorUA)) {
            throw new BEIDClientEnvironmentException('Navigator UA must be a string');
        }
        $this->navigatorUA = $navigatorUA;
    }

    /**
     * Get the navigator (browser) user agent name
     *
     * @return string
     */
    public function getNavigatorName() {
        return $this->navigatorName;
    }
    /**
     * Set the navigator bame
     *
     * @param string $navigatorName
     */
    public function setNavigatorName($navigatorName) {
        if (! is_string($navigatorName)) {
            throw new BEIDClientEnvironmentException('Navigator name must be a string');
        }
        $this->navigatorName = $navigatorName;
    }

    /**
     * Get the navigator version string
     *
     * @return string
     */
    public function getNavigatorVersion() {
        return $this->navigatorVersion;
    }
    /**
     * Set the navigator version
     *
     * @param string $navigatorVersion
     */
    public function setNavigatorVersion($navigatorVersion) {
        if (! is_string($navigatorVersion)) {
            throw new BEIDClientEnvironmentException('Navigator version must be a string');
        }
        $this->navigatorVersion = $navigatorVersion;
    }

    public function setEidReaders($readers) {
        $this->readers = $readers;
    }
    public function getEidReaders() {
        return $this->readers;
    }
}
?>
