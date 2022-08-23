<?php
class JsonTool
{
    /**
     * @param mixed $value
     * @param bool $prettyPrint
     * @returns string
     * @throws JsonException
     */
    public static function encode($value, $prettyPrint = false)
    {
        $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
        if (defined('JSON_THROW_ON_ERROR')) {
            $flags |= JSON_THROW_ON_ERROR; // Throw exception on error if supported
        }
        if ($prettyPrint) {
            $flags |= JSON_PRETTY_PRINT;
        }
        return json_encode($value, $flags);
    }

    /**
     * @param string $value
     * @returns mixed
     * @throws JsonException
     */
    public static function decode($value)
    {
        if (defined('JSON_THROW_ON_ERROR')) {
            // JSON_THROW_ON_ERROR is supported since PHP 7.3
            return json_decode($value, true, 512, JSON_THROW_ON_ERROR);
        }

        $decoded = json_decode($value, true);
        if ($decoded === null) {
            throw new UnexpectedValueException('Could not parse JSON: ' . json_last_error_msg(), json_last_error());
        }
        return $decoded;
    }
}
