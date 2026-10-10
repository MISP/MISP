<?php
class GpgTool
{
    /** @var CryptGpgExtended */
    private $gpg;

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
        if (empty($homedir)) {
            throw new Exception("Configuration option 'GnuPG.homedir' is not set, Crypt_GPG cannot be initialized.");
        }

        $options = [
            'homedir' => $homedir,
            'gpgconf' => Configure::read('GnuPG.gpgconf'),
            'binary' => Configure::read('GnuPG.binary') ?: '/usr/bin/gpg',
        ];

        return new CryptGpgExtended($options);
    }

    public function __construct(CryptGpgExtended $gpg = null)
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
        try {
            $response = $this->keyServerLookup($uri);
        } catch (HttpSocketHttpException $e) {
            if ($e->getCode() === 404) {
                return [];
            }
            throw $e;
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
        try {
            $response = $this->keyServerLookup($uri);
        } catch (HttpSocketHttpException $e) {
            if ($e->getCode() === 404) {
                return null;
            }
            throw $e;
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
        $this->gpg->importKey($keyData);
        return $primaryKey->getFingerprint();
    }

    /**
     * Parses the machine readable index of a HKP key server (`op=index&options=mr`),
     * which is one `pub` line per key followed by one `uid` line per identity
     * that key carries.
     *
     * @param string $body
     * @return array Each key as ['fingerprint', 'key_id', 'date', 'address'],
     *               'address' holding every identity, one per line.
     */
    private function extractKeySearch($body)
    {
        $final = array();
        $temp = array();
        $now = time();
        $lines = explode("\n", $body);
        foreach ($lines as $line) {
            $parts = explode(":", $line);

            if ($parts[0] === 'pub') {
                if (!empty($temp)) {
                    $final[] = $temp;
                    $temp = array();
                }

                $flags = isset($parts[6]) ? $parts[6] : '';
                if (strpos($flags, 'r') !== false || strpos($flags, 'd') !== false || strpos($flags, 'e') !== false) {
                    continue; // skip if key is expired, revoked or disabled
                }

                $expiration = isset($parts[5]) ? $parts[5] : '';
                if ($expiration !== '' && (int)$expiration < $now) {
                    continue;
                }

                $temp = array(
                    'fingerprint' => $parts[1],
                    'key_id' => substr($parts[1], -8),
                    'date' => date('Y-m-d', (int)$parts[4]),
                    'address' => array(),
                );

            } else if ($parts[0] === 'uid' && !empty($temp)) {
                // A key usually carries several identities - keep them all, the
                // one the search matched is not necessarily the last one listed.
                $address = urldecode($parts[1]);
                if (!in_array($address, $temp['address'], true)) {
                    $temp['address'][] = $address;
                }
            }
        }

        if (!empty($temp)) {
            $final[] = $temp;
        }

        foreach ($final as &$key) {
            $key['address'] = implode("\n", $key['address']);
        }
        unset($key);

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
            return $this->gpg->enarmor($response->body());
        } catch (Exception $e) {
            // pass, continue to direct method
        }

        $directUrl = "https://$domain/.well-known/openpgpkey/hu/$localPartHash";
        try {
            $response = $this->keyServerLookup($directUrl);
        } catch (HttpSocketHttpException $e) {
            if ($e->getCode() === 404) {
                throw new NotFoundException("Key not found");
            }
            throw $e;
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
     * @return HttpSocketResponseExtended
     * @throws HttpSocketHttpException
     * @throws Exception
     */
    private function keyServerLookup($uri)
    {
        App::uses('SyncTool', 'Tools');
        $syncTool = new SyncTool();
        $HttpSocket = $syncTool->createHttpSocket(['compress' => true]);
        $response = $HttpSocket->get($uri);
        if (!$response->isOk()) {
            throw new HttpSocketHttpException($response, $uri);
        }
        return $response;
    }
}
