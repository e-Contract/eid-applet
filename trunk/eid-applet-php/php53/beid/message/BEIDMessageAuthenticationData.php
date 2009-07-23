<?php
/**
 * Authentication data message
 *
 * @package BEIDApplet
 * @author Bart Hanssens
 * @copyright 2009, Fedict
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt LGPL 3.0 license
 *
 * $Id$
 */

class BEIDMessageAuthenticationData extends BEIDMessage {
    private $sizeSalt;
    private $sizeSignature;

    const LEGAL_NOTICE =
    "Declaration of authentication intension.\nThe following data should be interpreted as an authentication challenge.\n";

    public function getSaltSize() {
        return $this->sizeSalt;
    }
    public function setSaltSize($sizeSalt) {
        if (! is_int($sizeSalt)) {
            throw new BEIDMessageException('Size for salt must be integer');
        }
        if ($sizeSalt < 0) {
            throw new BEIDMessageException('Size for salt must >= 0');
        }
        $this->sizeSalt = $sizeSalt;
    }

    public function getSignatureSize() {
        return $this->sizeSignature;
    }
    public function setSignatureSize($sizeSignature) {
        if (! is_int($sizeSignature)) {
            throw new BEIDMessageException('Size for signature must be integer');
        }
        if ($sizeSignature < 0) {
            throw new BEIDMessageException('Size for signature must >= 0');
        }
        $this->sizeSignature = $sizeSignature;
    }

    /**
     * @todo add more exception handling code
     */
    public function getAuthentication() {
        $stream = HttpResponse::getRequestBodyStream();

        $saltSize = $this->getSaltSize();
        $salt = stream_get_contents($stream, $saltSize);

        $signatureSize = $this->getSignatureSize();
        $signature = stream_get_contents($stream, $signatureSize);

        $cert = stream_get_contents($stream);
        $pem = BEIDHelperConvert::certToPEM($cert);
        $cert = openssl_x509_read($pem);
        
        $challenge = $_SESSION['Challenge'];
        $toBeSigned = $salt . self::LEGAL_NOTICE . $challenge;

        $pubkey = openssl_get_publickey($cert);
        $result = openssl_verify($toBeSigned, $signature, $pubkey);
        openssl_x509_free($cert);
       
        switch($result) {
            case 1:
                BEIDHelperLogger::logger('Signature OK');
                break;
            case 0:
                BEIDHelperLogger::logger('Signature not correct');
                break;
            case -1:
                throw new BEIDMessageException('Unknown error when verifying signature');
                break;
        }
    }

    public function __construct() {
        parent::__construct();
        $this->setProtocolType(BEIDMessageType::AUTH_DATA);
    }
}
?>
