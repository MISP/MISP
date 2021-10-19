<?php
class JsonTool
{
    /**
     * @param mixed $value
     * @param bool $prettyPrint
     * @returns string
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
}
