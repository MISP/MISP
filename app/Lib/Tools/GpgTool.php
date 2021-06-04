<?php
class GpgTool
{
    /**
     * @return CryptGpgExtended
     * @throws Exception
     */
    public static function initializeGpg()
    {
        if (!class_exists('Crypt_GPG')) {
            // 'Crypt_GPG' class cannot be autoloaded, try to require from include_path.
            if (!stream_resolve_include_path('Crypt/GPG.php')) {
                throw new Exception("Crypt_GPG is not installed.");
            }
            require_once 'Crypt/GPG.php';
        }

        require_once __DIR__ . '/CryptGpgExtended.php';

        $homedir = Configure::read('GnuPG.homedir');
        if ($homedir === null) {
            throw new Exception("Configuration option 'GnuPG.homedir' is not set, Crypt_GPG cannot be initialized.");
        }

        $options = array(
            'homedir' => $homedir,
            'gpgconf' => Configure::read('GnuPG.gpgconf'),
            'binary' => Configure::read('GnuPG.binary') ?: '/usr/bin/gpg',
        );

        return new CryptGpgExtended($options);
    }

    /** @var CryptGpgExtended */
    private $gpg;

    public function __construct($gpg)
    {
        $this->gpg = $gpg;
    }

    /**
     * @param string $search
     * @return array
     * @throws Exception
     */
    public function searchGpgKey($search)
    {
        $uri = 'https://openpgp.circl.lu/pks/lookup?search=' . urlencode($search) . '&op=index&fingerprint=on&options=mr';
        $response = $this->keyServerLookup($uri);
        if ($response->code == 404) {
            return array(); // no keys found
        } else if ($response->code != 200) {
            throw new Exception("Fetching the '$uri' failed with HTTP error {$response->code}: {$response->reasonPhrase}");
        }
        return $this->extractKeySearch($response->body);
    }

    /**
     * @param string $fingerprint
     * @return string|null
     * @throws Exception
     */
    public function fetchGpgKey($fingerprint)
    {
        $uri = 'https://openpgp.circl.lu/pks/lookup?search=0x' . urlencode($fingerprint) . '&op=get&options=mr';
        $response = $this->keyServerLookup($uri);
        if ($response->code == 404) {
            return null; // key with given fingerprint not found
        } else if ($response->code != 200) {
            throw new Exception("Fetching the '$uri' failed with HTTP error {$response->code}: {$response->reasonPhrase}");
        }

        $key = $response->body;

        if ($this->gpg) {
            $fetchedFingerprint = $this->validateGpgKey($key);
            if (strtolower($fingerprint) !== strtolower($fetchedFingerprint)) {
                throw new Exception("Requested fingerprint do not match with fetched key fingerprint ($fingerprint != $fetchedFingerprint)");
            }
        }

        return $key;
    }

    /**
     * Validates PGP key
     * @param string $keyData
     * @return string Primary key fingerprint
     * @throws Exception
     */
    public function validateGpgKey($keyData)
    {
        if (!$this->gpg instanceof CryptGpgExtended) {
            throw new InvalidArgumentException("Valid CryptGpgExtended instance required.");
        }
        $fetchedKeyInfo = $this->gpg->keyInfo($keyData);
        if (count($fetchedKeyInfo) !== 1) {
            throw new Exception("Multiple keys found");
        }
        $primaryKey = $fetchedKeyInfo[0]->getPrimaryKey();
        if (empty($primaryKey)) {
            throw new Exception("No primary key found");
        }
        return $primaryKey->getFingerprint();
    }

    /**
     * @param string $body
     * @return array
     */
    private function extractKeySearch($body)
    {
        $final = array();
        $lines = explode("\n", $body);
        foreach ($lines as $line) {
            $parts = explode(":", $line);

            if ($parts[0] === 'pub') {
                if (!empty($temp)) {
                    $final[] = $temp;
                    $temp = array();
                }

                if (strpos($parts[6], 'r') !== false || strpos($parts[6], 'd') !== false || strpos($parts[6], 'e') !== false) {
                    continue; // skip if key is expired, revoked or disabled
                }

                $temp = array(
                    'fingerprint' => $parts[1],
                    'key_id' => substr($parts[1], -8),
                    'date' => date('Y-m-d', $parts[4]),
                );

            } else if ($parts[0] === 'uid' && !empty($temp)) {
                $temp['address'] = urldecode($parts[1]);
            }
        }

        if (!empty($temp)) {
            $final[] = $temp;
        }

        return $final;
    }

    /**
     * @see https://tools.ietf.org/html/draft-koch-openpgp-webkey-service-10
     * @param string $email
     * @return string
     * @throws Exception
     */
    public function wkd($email)
    {
        if (!$this->gpg instanceof CryptGpgExtended) {
            throw new InvalidArgumentException("Valid CryptGpgExtended instance required.");
        }

        $parts = explode('@', $email);
        if (count($parts) !== 2) {
            throw new InvalidArgumentException("Invalid e-mail address provided.");
        }

        list($localPart, $domain) = $parts;
        $localPart = strtolower($localPart);
        $localPartHash = $this->zbase32(sha1($localPart, true));

        $advancedUrl = "https://openpgpkey.$domain/.well-known/openpgpkey/" . strtolower($domain) . "/hu/$localPartHash";
        try {
            $response = $this->keyServerLookup($advancedUrl);
            return $this->processWkdResponse($response);
        } catch (Exception $e) {
            // pass, continue to direct method
        }

        $directUrl = "https://$domain/.well-known/openpgpkey/hu/$localPartHash";
        $response = $this->keyServerLookup($directUrl);
        return $this->processWkdResponse($response);
    }

    /**
     * @param HttpSocketResponse $response
     * @return string
     * @throws Crypt_GPG_Exception
     * @throws Crypt_GPG_InvalidOperationException
     */
    private function processWkdResponse(HttpSocketResponse $response)
    {
        if ($response->code == 404) {
            throw new NotFoundException("Key not found");
        } else if (!$response->isOk()) {
            throw new Exception("Fetching the WKD failed with HTTP error {$response->code}: {$response->reasonPhrase}");
        }

        return $this->gpg->enarmor($response->body());
    }

    /**
     * Converts data to zbase32 string.
     *
     * @see http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
     * @param string $data
     * @return string
     */
    private function zbase32($data)
    {
        $chars = 'ybndrfg8ejkmcpqxot1uwisza345h769'; // lower-case
        $res = '';
        $remainder = 0;
        $remainderSize = 0;

        for ($i = 0; $i < strlen($data); $i++) {
            $b = ord($data[$i]);
            $remainder = ($remainder << 8) | $b;
            $remainderSize += 8;
            while ($remainderSize > 4) {
                $remainderSize -= 5;
                $c = $remainder & (31 << $remainderSize);
                $c >>= $remainderSize;
                $res .= $chars[$c];
            }
        }
        if ($remainderSize > 0) {
            // remainderSize < 5:
            $remainder <<= (5 - $remainderSize);
            $c = $remainder & 31;
            $res .= $chars[$c];
        }
        return $res;
    }

    /**
     * @param string $uri
     * @return HttpSocketResponse
     * @throws Exception
     */
    private function keyServerLookup($uri)
    {
        App::uses('SyncTool', 'Tools');
        $syncTool = new SyncTool();
        $HttpSocket = $syncTool->setupHttpSocket();
        $response = $HttpSocket->get($uri);
        if ($response === false) {
            throw new Exception("Could not fetch '$uri'.");
        }
        return $response;
    }
}
