<?php
class CryptGpgExtended extends Crypt_GPG
{
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
}
