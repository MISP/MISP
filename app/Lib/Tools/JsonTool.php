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
        $flags = defined('JSON_THROW_ON_ERROR') ? JSON_THROW_ON_ERROR : 0; // Throw exception on error if supported
        return json_decode($value, true, 512, $flags);
    }
}
