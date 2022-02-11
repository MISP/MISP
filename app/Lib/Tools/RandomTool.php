<?php

class RandomTool
{
    /**
     * Generate a random string
     *
     * Generate a random string, using a cryptographically secure
     * pseudorandom number generator (random_int)
     *
     * For PHP 7, random_int is a PHP core function
     * For PHP 5.x, depends on https://github.com/paragonie/random_compat
     *
     * @link https://paragonie.com/b/JvICXzh_jhLyt4y3
     *
     * @param bool $crypto_secure - If a cryptographically secure or a fast random number generator should be used
     * @param int $length - How long should our random string be?
     * @param string $charset - A string of all possible characters to choose from
     * @return string
     * @throws Exception
     */
    public function random_str($crypto_secure = true, $length = 32, $charset = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
    {
        // Type checks:
        if (!is_bool($crypto_secure)) {
            throw new InvalidArgumentException('random_str - Argument 1 - expected a boolean');
        }
        if (!is_numeric($length)) {
            throw new InvalidArgumentException('random_str - Argument 2 - expected an integer');
        }
        if (!is_string($charset)) {
            throw new InvalidArgumentException('random_str - Argument 3 - expected a string');
        }

        if ($length < 1) {
            // Just return an empty string. Any value < 1 is meaningless.
            return '';
        }

        // Remove duplicate characters from $charset
        $charset = count_chars($charset, 3);

        // This is the maximum index for all of the characters in the string $charset
        $charset_max = strlen($charset) - 1;
        if ($charset_max < 1) {
            // Avoid letting users do: random_str($int, 'a'); -> 'aaaaa...'
            throw new LogicException('random_str - Argument 3 - expected a string that contains at least 2 distinct characters');
        }
        // Now that we have good data, this is the meat of our function:
        $random_str = '';
        for ($i = 0; $i < $length; ++$i) {
            $r = $crypto_secure ? random_int(0, $charset_max) : mt_rand(0, $charset_max);
            $random_str .= $charset[$r];
        }
        return $random_str;
    }
}
