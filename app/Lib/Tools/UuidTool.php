<?php

// import compatibility library for PHP < 7.0
if (!function_exists('random_bytes')) {
    if (file_exists(APP . 'Lib' . DS . 'random_compat' . DS . 'lib' . DS . 'random.php')) {
        require_once(APP . 'Lib' . DS . 'random_compat' . DS . 'lib' . DS . 'random.php');
    }
}

// Code inspired from https://github.com/jchook/uuid-v4
class UuidTool
{
    // Buffering random_bytes() speeds up generation of many uuids at once
    const BUFFER_SIZE = 512;

    protected static $buf;
    protected static $bufIdx = self::BUFFER_SIZE;

    /**
     * @return string
     * @throws Exception
     */
    public static function v4()
    {
        $b = self::randomBytes(16);
        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
    }

    /**
     * @param int $n
     * @return string
     * @throws Exception
     */
    protected static function randomBytes($n)
    {
        if (self::$bufIdx + $n >= self::BUFFER_SIZE) {
            self::$buf = random_bytes(self::BUFFER_SIZE);
            self::$bufIdx = 0;
        }
        $idx = self::$bufIdx;
        self::$bufIdx += $n;
        return substr(self::$buf, $idx, $n);
    }
}
