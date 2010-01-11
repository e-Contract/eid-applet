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

    /* used in authentication */
    const LEGAL_NOTICE =
    "Declaration of authentication intension.\nThe following data should be interpreted as an authentication challenge.\n";

    /**
     * Get the size of the salt (number of bytes)
     *
     * @return int
     */
    public function getSaltSize() {
        return $this->sizeSalt;
    }
    /**
     * Set the size of the salt
     *
     * @param int $sizeSalt
     */
    public function setSaltSize($sizeSalt) {
        if (! is_int($sizeSalt)) {
            throw new BEIDMessageException('Size for salt must be integer');
        }
        if ($sizeSalt < 0) {
            throw new BEIDMessageException('Size for salt must >= 0');
        }
        $this->sizeSalt = $sizeSalt;
    }

    /**
     * Get signature size (number of bytes)
     *
     * @return int
     */
    public function getSignatureSize() {
        return $this->sizeSignature;
    }
    /**
     * Set signature size
     *
     * @param int $sizeSignature
     */
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
     * Get authentication
     *
     * @param HttpMessage $request
     * @todo add more exception handling code
     */
    public function getAuthentication(HttpMessage $request) {
        $stream = HttpResponse::getRequestBodyStream();

        unset($_SESSION['Identifier']);

        /* TODO : cleanup */
        $saltSize = $request->getHeader(BEIDMessageHeader::SALT_SIZE);
        $signatureSize = $request->getHeader(BEIDMessageHeader::SIG_SIZE);

        $this->setSaltSize(intval($saltSize));
        $this->setSignatureSize(intval($signatureSize));


        $saltSize = $this->getSaltSize();
        $salt = stream_get_contents($stream, $saltSize);

        $signatureSize = $this->getSignatureSize();
        $signature = stream_get_contents($stream, $signatureSize);

        /* citizen's authentication certificate that was used to sign the challenge */
        $cert = stream_get_contents($stream);
        $pem = BEIDHelperConvert::certToPEM($cert);
        $cert = openssl_x509_read($pem);
        
        $challenge = $_SESSION['Challenge'];
        $toBeSigned = $salt . self::LEGAL_NOTICE . $challenge;
        unset($_SESSION['Challenge']);

        /* verification happens here */
        $pubkey = openssl_get_publickey($cert);
        $result = openssl_verify($toBeSigned, $signature, $pubkey);

        if ($result == 1) {
            $arr = openssl_x509_parse($cert);
            $this->identifier = $arr['subject']['serialNumber'];
            $_SESSION['Identifier'] = $this->identifier;
        }
        openssl_x509_free($cert);

        if ($result < 0) {
            throw new BEIDMessageException('Unknown error when verifying signature');
        }
    }

    /**
     * Constructor
     */
    public function __construct() {
        parent::__construct();
        $this->setProtocolType(BEIDMessageType::AUTH_DATA);
    }
}
?>
