<?php

class BetterSecurity
{
    const METHOD = 'AES-256-GCM';
    const TAG_SIZE = 16;

    /**
     * @param string $plain
     * @param string $key
     * @return string
     * @throws Exception
     */
    public static function encrypt($plain, $key)
    {
        if (strlen($key) < 32) {
            throw new Exception('Invalid key, key must be at least 256 bits (32 bytes) long.');
        }

        // Generate the encryption key.
        $key = hash('sha256', $key, true);

        $ivlen = openssl_cipher_iv_length(self::METHOD);
        $iv = openssl_random_pseudo_bytes($ivlen);
        if ($iv === false) {
            throw new Exception('Could not generate random bytes.');
        }
        $ciphertext = openssl_encrypt($plain, self::METHOD, $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($ciphertext === false) {
            throw new Exception('Could not encrypt.');
        }
        return $iv . $tag . $ciphertext;
    }

    /**
     * @param string $cipher
     * @param string $key
     * @return string
     * @throws Exception
     */
    public static function decrypt($cipher, $key)
    {
        if (strlen($key) < 32) {
            throw new Exception('Invalid key, key must be at least 256 bits (32 bytes) long.');
        }
        if (empty($cipher)) {
            throw new Exception('The data to decrypt cannot be empty.');
        }

        // Generate the encryption key.
        $key = hash('sha256', $key, true);

        $ivSize = openssl_cipher_iv_length(self::METHOD);

        // Split out hmac for comparison
        $iv = substr($cipher, 0, $ivSize);
        $tag = substr($cipher, $ivSize, self::TAG_SIZE);
        $cipher = substr($cipher, $ivSize + self::TAG_SIZE);

        $decrypted = openssl_decrypt($cipher, self::METHOD, $key, true, $iv, $tag);
        if ($decrypted === false) {
            throw new Exception('Could not decrypt. Maybe invalid encryption key?');
        }
        return $decrypted;
    }
}
