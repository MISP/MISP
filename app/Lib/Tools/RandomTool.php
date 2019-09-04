<?php
declare(strict_types=1);

class RandomTool
{
    /**
     * Generate a random string
     *
     * Generate a random string, using a cryptographically secure
     * pseudorandom number generator (random_int)
     *
     *
     * @link https://paragonie.com/b/JvICXzh_jhLyt4y3
     *
     * @param bool $crypto_secure - If a cryptographically secure or a fast random number generator should be used
     * @param int $length - How long should our random string be?
     * @param string $charset - A string of all possible characters to choose from
     * @return string
     */
    public function random_str(bool $crypto_secure = true, int $length = 32, string $charset = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
    {
        if ($length < 1) {
            // Just return an empty string. Any value < 1 is meaningless.
            return '';
        }

        // Remove duplicate characters from $charset
        $split = str_split($charset);
        $charset = implode('', array_unique($split));

        // This is the maximum index for all of the characters in the string $charset
        $charset_max = strlen($charset) - 1;
        if ($charset_max < 1) {
            // Avoid letting users do: random_str($int, 'a'); -> 'aaaaa...'
            throw new LogicException(
                'random_str - Argument 3 - expected a string that contains at least 2 distinct characters'
            );
        }
        // Now that we have good data, this is the meat of our function:
        $random_str = '';
        for ($i = 0; $i < $length; ++$i) {
            if ($crypto_secure) {
                $r = random_int(0, $charset_max);
            } else {
                $r = mt_rand(0, $charset_max);
            }
            $random_str .= $charset[$r];
        }
        return $random_str;
    }
}
