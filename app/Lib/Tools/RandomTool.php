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
     * @param bool $cryptoSecure - If a cryptographically secure or a fast random number generator should be used
     * @param int $length - How long should our random string be?
     * @param string $charset - A string of all possible characters to choose from
     * @return string
     * @throws Exception
     */
    public static function random_str(bool $cryptoSecure = true, int $length = 32, string $charset = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
    {
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

        if (PHP_VERSION_ID >= 80300) {
            $randomizer = new \Random\Randomizer();
            return $randomizer->getBytesFromString($charset, $length);
        }

        // Now that we have good data, this is the meat of our function:
        $random_str = '';
        for ($i = 0; $i < $length; ++$i) {
            $r = $cryptoSecure ? random_int(0, $charset_max) : mt_rand(0, $charset_max);
            $random_str .= $charset[$r];
        }
        return $random_str;
    }
}
