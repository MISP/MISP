<?php
class CryptGpgExtended extends Crypt_GPG
{
    public function __construct(array $options = array())
    {
        if (!method_exists($this, '_prepareInput')) {
            $reflector = new \ReflectionClass('Crypt_GPG');
            $classPath = $reflector->getFileName();
            throw new Exception("Crypt_GPG class from '$classPath' is too old, at least version 1.6.1 is required.");
        }
        parent::__construct($options);
    }

    /**
     * Export the smallest public key possible from the keyring.
     *
     * This removes all signatures except the most recent self-signature on each user ID. This option is the same as
     * running the --edit-key command "minimize" before export except that the local copy of the key is not modified.
     *
     * The exported key remains on the keyring. To delete the public key, use
     * {@link Crypt_GPG::deletePublicKey()}.
     *
     * If more than one key fingerprint is available for the specified
     * <kbd>$keyId</kbd> (for example, if you use a non-unique uid) only the
     * first public key is exported.
     *
     * @param string  $keyId either the full uid of the public key, the email
     *                       part of the uid of the public key or the key id of
     *                       the public key. For example,
     *                       "Test User (example) <test@example.com>",
     *                       "test@example.com" or a hexadecimal string.
     * @param boolean $armor optional. If true, ASCII armored data is returned;
     *                       otherwise, binary data is returned. Defaults to
     *                       true.
     *
     * @return string the public key data.
     *
     * @throws Crypt_GPG_KeyNotFoundException if a public key with the given
     *         <kbd>$keyId</kbd> is not found.
     *
     * @throws Crypt_GPG_Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    public function exportPublicKeyMinimal($keyId, $armor = true)
    {
        $fingerprint = $this->getFingerprint($keyId);

        if ($fingerprint === null) {
            throw new Crypt_GPG_KeyNotFoundException(
                'Key not found: ' . $keyId,
                self::ERROR_KEY_NOT_FOUND,
                $keyId
            );
        }

        $keyData   = '';
        $operation = '--export';
        $operation .= ' ' . escapeshellarg($fingerprint);

        $arguments = array('--export-options', 'export-minimal');
        if ($armor) {
            $arguments[] = '--armor';
        }

        $this->engine->reset();
        $this->engine->setPins($this->passphrases);
        $this->engine->setOutput($keyData);
        $this->engine->setOperation($operation, $arguments);
        $this->engine->run();

        return $keyData;
    }

    /**
     * Return key info without importing it when GPG supports --import-options show-only, otherwise just import and
     * then return details.
     *
     * @param string $key
     * @return Crypt_GPG_Key[]
     * @throws Crypt_GPG_Exception
     * @throws Crypt_GPG_InvalidOperationException
     */
    public function keyInfo($key)
    {
        $version = $this->engine->getVersion();
        if (version_compare($version, '2.1.23', 'le')) {
            $importResult = $this->importKey($key);
            $keys = [];
            foreach ($importResult['fingerprints'] as $fingerprint) {
                foreach ($this->getKeys($fingerprint) as $key) {
                    $keys[] = $key;
                }
            }
            return $keys;
        }

        $input = $this->_prepareInput($key, false, false);

        $output = '';
        $this->engine->reset();
        $this->engine->setInput($input);
        $this->engine->setOutput($output);
        $this->engine->setOperation('--import', ['--import-options', 'show-only', '--with-colons']);
        $this->engine->run();

        $keys   = array();
        $key    = null; // current key
        $subKey = null; // current sub-key

        foreach (explode(PHP_EOL, $output) as $line) {
            $lineExp = explode(':', $line);

            if ($lineExp[0] === 'pub') {
                // new primary key means last key should be added to the array
                if ($key !== null) {
                    $keys[] = $key;
                }

                $key = new Crypt_GPG_Key();

                $subKey = Crypt_GPG_SubKey::parse($line);
                $key->addSubKey($subKey);

            } elseif ($lineExp[0] === 'sub') {
                $subKey = Crypt_GPG_SubKey::parse($line);
                $key->addSubKey($subKey);

            } elseif ($lineExp[0] === 'fpr') {
                $fingerprint = $lineExp[9];

                // set current sub-key fingerprint
                $subKey->setFingerprint($fingerprint);

            } elseif ($lineExp[0] === 'uid') {
                $string = stripcslashes($lineExp[9]); // as per documentation
                $userId = new Crypt_GPG_UserId($string);

                if ($lineExp[1] === 'r') {
                    $userId->setRevoked(true);
                }

                $key->addUserId($userId);
            }
        }

        // add last key
        if ($key !== null) {
            $keys[] = $key;
        } else {
            throw new Crypt_GPG_Exception("Key data provided, but gpg process output could not be parsed: $output");
        }

        return $keys;
    }

    /**
     * @param string $key
     * @return string
     * @throws Crypt_GPG_Exception
     * @throws Crypt_GPG_InvalidOperationException
     */
    public function enarmor($key)
    {
        $input = $this->_prepareInput($key, false, false);

        $armored = '';
        $this->engine->reset();
        $this->engine->setInput($input);
        $this->engine->setOutput($armored);
        $this->engine->setOperation('--enarmor');
        $this->engine->run();

        return $armored;
    }
}
