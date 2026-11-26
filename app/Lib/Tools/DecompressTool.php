<?php
App::uses('DecompressLimitException', 'Tools');

class DecompressTool
{
    // Deflate expands at most about 1032:1, so one slice can overshoot the
    // limit by about 8 MB. Brotli and zstd are left out: a few bytes of either
    // can expand to megabytes, so slicing their input bounds nothing.
    const SLICE_SIZE = 8192;

    /**
     * @return string[]
     */
    public static function supportedEncodings()
    {
        return function_exists('inflate_init') ? ['gzip'] : [];
    }

    /**
     * Security.max_decompressed_size when set, else the PHP memory limit in force.
     *
     * @return int|null null for no limit
     */
    public static function limit()
    {
        $configured = (int)Configure::read('Security.max_decompressed_size');
        return $configured > 0 ? $configured : self::memoryLimit();
    }

    /**
     * @return int|null the PHP memory limit in bytes, null when unlimited
     */
    public static function memoryLimit()
    {
        return self::iniToBytes(ini_get('memory_limit'));
    }

    /**
     * @param string|int|false $value a php.ini size such as -1, 134217728, 512K, 128M, 2G
     * @return int|null Null for unlimited
     */
    public static function iniToBytes($value)
    {
        $value = strtolower(trim((string)$value));
        if ($value === '' || $value === '-1') {
            return null;
        }
        $number = (int)$value;
        switch (substr($value, -1)) {
            case 'g':
                $number *= 1024;
                // no break
            case 'm':
                $number *= 1024;
                // no break
            case 'k':
                $number *= 1024;
        }
        return $number > 0 ? $number : null;
    }

    /**
     * @param string $encoding
     * @param string $data
     * @param int|null $maxBytes null or 0 for no limit
     * @return string
     * @throws DecompressLimitException when the decoded data exceeds $maxBytes
     * @throws InvalidArgumentException for invalid data or an unsupported encoding
     */
    public static function decode($encoding, $data, $maxBytes = null)
    {
        if (!in_array($encoding, self::supportedEncodings(), true)) {
            throw new InvalidArgumentException("Unsupported content encoding '$encoding'.");
        }
        $maxBytes = $maxBytes ? (int)$maxBytes : null;
        $ctx = inflate_init(ZLIB_ENCODING_GZIP);
        if ($ctx === false) {
            throw new InvalidArgumentException('Invalid compressed data.');
        }
        $out = '';
        $length = strlen($data);
        for ($offset = 0; $offset < $length; $offset += self::SLICE_SIZE) {
            $chunk = @inflate_add($ctx, substr($data, $offset, self::SLICE_SIZE), ZLIB_SYNC_FLUSH);
            if ($chunk === false) {
                throw new InvalidArgumentException('Invalid compressed data.');
            }
            $out .= $chunk;
            if ($maxBytes !== null && strlen($out) > $maxBytes) {
                throw new DecompressLimitException("Decompressed data exceeds the limit of $maxBytes bytes.");
            }
            if (inflate_get_status($ctx) === ZLIB_STREAM_END) {
                break;
            }
        }
        if (inflate_get_status($ctx) !== ZLIB_STREAM_END) {
            throw new InvalidArgumentException('Invalid compressed data.');
        }
        return $out;
    }
}
