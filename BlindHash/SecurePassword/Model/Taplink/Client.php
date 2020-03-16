<?php

class Client
{

    public $appID;
    public $userAgent;
    public $servers;
    public $retryCount;
    public $requestCounter = 0;
    public $retryCounter = 0;
    public $errorCounter = 0;
    public $timeout;
    public $helper;
    public static $hashAlgorithm = 'sha512';
    public static $defaultServer = 'api.taplink.co';

    function __construct($appID, $retryCount = 2, $timeout = 1000, $serverList = array(), $helper)
    {
        $this->appID = $appID;
        $this->userAgent = 'TapLink/1.0 php/' . phpversion();
        $this->retryCount = $retryCount;
        $this->timeout = $timeout;
        $this->servers = (empty($serverList)) ? [self::$defaultServer] : $serverList;
        $this->helper = $helper;
    }

    function __destruct()
    {
        $this->helper->updatedBlindHashRequestCounters((object) array('total_error_count' => $this->errorCounter, 'total_request_count' => $this->requestCounter, 'total_retry_count' => $this->retryCounter));
    }

    public function getSalt($hash1Hex, $versionID = null)
    {
        return $this->get(sprintf('%s/%s/%s', $this->appID, $hash1Hex, $versionID ? : ''));
    }

    public function verifyPassword($hash1Hex, $hash2ExpectedHex, $versionId = null)
    {
        $res = $this->getSalt($hash1Hex, $versionId);
        if (!$res->err) {
            $res->hash2Hex = hash_hmac(self::$hashAlgorithm, hex2bin($hash1Hex), hex2bin($res->salt2Hex));
        }
        $res->matched = !$res->err && $res->hash2Hex === $hash2ExpectedHex;
        if ($res->matched && $res->newVersionId && $res->newSalt2Hex) {
            $res->newHash2Hex = hash_hmac(self::$hashAlgorithm, hex2bin($hash1Hex), hex2bin($res->newSalt2Hex));
        }
        return $res;
    }

    public function newPassword($hash1Hex)
    {
        $res = $this->getSalt($hash1Hex);
        if (!$res->err) {
            $res->hash2Hex = hash_hmac(self::$hashAlgorithm, hex2bin($hash1Hex), hex2bin($res->salt2Hex));
        }
        return $res;
    }

    private function getServer($attempts = 0)
    {
        if (empty($this->servers)) {
            return self::$defaultServer;
        }
        if (!$attempts) {
            return $this->servers[0];
        }
        return $this->servers[$attempts % count($this->servers)];
    }

    private function makeURL($url, $attempts = 0)
    {
        return sprintf('https://%s/%s', trim($this->getServer($attempts), '/'), ltrim($url, '/'));
    }

    private function get($url)
    {
        for ($i = 0; $i <= $this->retryCount; $i++) {
            $this->retryCounter = $i;
            $curlTimeout = $this->timeout + ($i * $this->timeout);
            foreach ($this->servers as $server) {
                $this->requestCounter++;
                $taplinkUrl = sprintf('https://%s/%s', trim($server, '/'), ltrim($url, '/'));
                $ch = curl_init($taplinkUrl);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT_MS, $curlTimeout);
                $verifyer = ($this->isLocalMachine()) ? false : true;
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $verifyer);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array(
                    'User-Agent: ' . $this->userAgent,
                    'Accept: application/json',
                ));
                $res = curl_exec($ch);
                $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);

                if ($status !== 0) {
                    if ($status !== 200) {
                        return new Response(['err' => true, 'errCode' => curl_errno($ch), 'errMsg' => curl_error($ch)]);
                    }

                    return new Response(json_decode($res, true));
                }
            }
        }
        $this->errorCounter++;
        return new Response(['err' => true, 'errCode' => -1, 'errMsg' => 'Request Timeout']);
    }

    /**
     * Check if current server is localhost or not
     * 
     * @return boolean
     */
    public function isLocalMachine()
    {
        $whitelist = array(
            '127.0.0.1',
            '::1'
        );
        return (in_array($_SERVER['REMOTE_ADDR'], $whitelist)) ? true : false;
    }

    /**
     * Verify AppId
     * @return boolean
     */
    public function verifyAppId()
    {
        return $this->get(sprintf('%s', $this->appID));
    }

    /**
     * Encrypt string
     * 
     * @param type $publicKeyHex
     * @param type $hashHex
     * @return string
     */
    public function encrypt($publicKeyHex, $hashHex)
    {
        if (!function_exists('\Sodium\crypto_box_seal') || strlen($publicKeyHex) < 64 || strlen($hashHex) < 1) {
            return $hashHex;
        }

	$crypt = \Sodium\crypto_box_seal(hex2bin($hashHex), hex2bin($publicKeyHex));
        return "Z" . bin2hex($crypt);
    }

    /**
     * Decrypt string 
     * 
     * @param type $publicKeyHex
     * @param type $privateKeyHex
     * @param type $cryptHex
     * @return string
     */
    public function decrypt($publicKeyHex, $privateKeyHex, $cryptHex)
    {
        if (!function_exists('\Sodium\crypto_box_seal') || strlen($publicKeyHex) < 64 || strlen($privateKeyHex) < 64) {
            if (strlen($cryptHex) > 0 && substr($cryptHex, 0, 1) === 'Z') {
                throw new Exception(__("Missing/Invalid Decryption Key - Decryption Key is required to remove BlindHash protection!"));
            }
            return $cryptHex;
        } else if (substr($cryptHex, 0, 1) !== 'Z') {
            return $cryptHex;
        }
        $ciphertext = hex2bin(substr($cryptHex, 1, strlen($cryptHex) - 1));
	$keypair = \Sodium\crypto_box_keypair_from_secretkey_and_publickey(hex2bin($privateKeyHex),hex2bin($publicKeyHex));
        $decrypt = \Sodium\crypto_box_seal_open($ciphertext, $keypair);
        return bin2hex($decrypt);
    }

    /**
     * Encryption Test
     * 
     * @return int
     */
    public function encryptTest()
    {
        if (!function_exists('\Sodium\crypto_box_seal')) {
            return false;
        }

        try {

            $message = "This is a test.";
            $keypair = hex2bin(
                '15b36cb00213373fb3fb03958fb0cc0012ecaca112fd249d3cf0961e311caac9' .
                'fb4cb34f74a928b79123333c1e63d991060244cda98affee14c3398c6d315574'
            );
            $publickey = hex2bin(
                'fb4cb34f74a928b79123333c1e63d991060244cda98affee14c3398c6d315574'
            );
            $crypt = \Sodium\crypto_box_seal($message, $publickey);
            $decrypt = \Sodium\crypto_box_seal_open($crypt, $keypair);

            return strcmp($message, $decrypt) === 0;
        } catch (Exception $ex) {
            return false;
        }
    }

    public function decryptTest($publicKeyHex, $privateKeyHex)
    {
	if (!function_exists('\Sodium\crypto_box_seal')) {
            return false;
        }

        try {
	    $calcPubKey = bin2hex(\Sodium\crypto_box_publickey_from_secretkey(hex2bin($privateKeyHex)));
	    if (strcasecmp($calcPubKey, $publicKeyHex) == 2) {
		return "Private Key produced a mismatched Public Key!".
			"<br> - Private Key: ".$privateKeyHex.
			"<br> - Configured Public Key: ".$publicKeyHex.
			"<br> - Calculated Public Key: ".$calcPubKey;
	    }


            $message = "This is a test.";
	    $keypair = \Sodium\crypto_box_keypair_from_secretkey_and_publickey(hex2bin($privateKeyHex),hex2bin($publicKeyHex));
            $publickey = hex2bin($publicKeyHex);
            $crypt = \Sodium\crypto_box_seal($message, $publickey);
            $decrypt = \Sodium\crypto_box_seal_open($crypt, $keypair);

            if (strcmp($message, $decrypt) === 0) {
		return "";
	    } else {
		return "While testing decryption, 'crypto_box_seal_open' succeeded, but the decrypted result did not match the original plaintext.".
			"<br> - Crypt Data: ".bin2hex($crypt).
			"<br> - Public Key: ".$publicKeyHex."<br> - Private Key: ".$privateKeyHex.
			"<br> - Message: '".$message."'<br> - Result: '".$decrypt."'";
	    }
        } catch (Exception $ex) {
            return $ex->getMessage();
        }
    }
}
