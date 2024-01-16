<?php

class BetterSecurity
{
    const METHOD = 'AES-256-GCM';
    const TAG_SIZE = 16;

    /**
     * @param string $plain
     * @param string $key Encryption key
     * @return string Cipher text with IV and tag
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
     * @param string $cipherText Cipher text with IV and tag
     * @param string $key Decryption key
     * @return string
     * @throws Exception
     */
    public static function decrypt($cipherText, $key)
    {
        if (strlen($key) < 32) {
            throw new Exception('Invalid key, key must be at least 256 bits (32 bytes) long.');
        }
        if (empty($cipherText)) {
            throw new Exception('The data to decrypt cannot be empty.');
        }

        // Generate the encryption key.
        $key = hash('sha256', $key, true);

        $ivSize = openssl_cipher_iv_length(self::METHOD);

        if (strlen($cipherText) < $ivSize + self::TAG_SIZE) {
            $length = strlen($cipherText);
            $minLength = $ivSize + self::TAG_SIZE;
            throw new Exception("Provided cipher text is too short, $length bytes provided, expected at least $minLength bytes.");
        }

        // Split out hmac for comparison
        $iv = substr($cipherText, 0, $ivSize);
        $tag = substr($cipherText, $ivSize, self::TAG_SIZE);
        $cipherText = substr($cipherText, $ivSize + self::TAG_SIZE);

        $decrypted = openssl_decrypt($cipherText, self::METHOD, $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($decrypted === false) {
            throw new Exception('Could not decrypt. Maybe invalid encryption key?');
        }
        return $decrypted;
    }
}
