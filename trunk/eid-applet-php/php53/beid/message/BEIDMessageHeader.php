<?php
/**
 * Message header class, containing a list of HTTP headers to be used in various messages
 *
 * @package BEIDApplet-PHP5
 * @author Bart Hanssens
 * @copyright 2009, Fedict
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt LGPL 3.0 license
 *
 * $Id$
 */

class BEIDMessageHeader {
    const VERSION = 'X-AppletProtocol-Version';
    const TYPE = 'X-AppletProtocol-Type';
    /* client environment */
    const JAVA_VERSION = 'X-AppletProtocol-JavaVersion';
    const JAVA_VENDOR = 'X-AppletProtocol-JavaVendor';
    const OS_NAME = 'X-AppletProtocol-OSName';
    const OS_ARCH = 'X-AppletProtocol-OSArch';
    const OS_VERSION = 'X-AppletProtocol-OSVersion';
    const NAVIGATOR_UA = 'X-AppletProtocol-NavigatorUserAgent';
    const NAVIGATOR_NAME = 'X-AppletProtocol-NavigatorAppName';
    const NAVIGATOR_VERSION = 'X-AppletProtocol-NavigatorAppVersion';
    /* ID */
    const ID_SIZE = 'X-AppletProtocol-IdentityFileSize';
    const INCLUDE_ADDRESS = 'X-AppletProtocol-IncludeAddress';
    const ADDRESS_SIZE = 'X-AppletProtocol-AddressFileSize';
    const INCLUDE_PHOTO = 'X-AppletProtocol-IncludePhoto';
    const PHOTO_SIZE = 'X-AppletProtocol-PhotoFileSize';
    const INCLUDE_CERTS = 'X-AppletProtocol-IncludeCertificates';
    const INTEGRITY_DATA = 'X-AppletProtocol-IncludeIntegrityData';
    /* authentication */
    const REMOVE_CARD = 'X-AppletProtocol-RemoveCard';
    const SALT_SIZE = 'X-AppletProtocol-SaltValueSize';
    const DIGEST_ALGO = 'X-AppletProtocol-DigestAlgo';
    const DIGEST_DESCRIPTION = 'X-AppletProtocol-Description';
    const SIG_SIZE = 'X-AppletProtocol-SignatureValueSize';
    const INCLUDE_HOSTNAME = 'X-AppletProtocol-IncludeHostname';
}
?>
