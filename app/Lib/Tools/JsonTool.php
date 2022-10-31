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
     * @throws UnexpectedValueException
     */
    public static function decode($value)
    {
        if (function_exists('simdjson_decode')) {
            // Use faster version of json_decode from simdjson PHP extension if this extension is installed
            try {
                return simdjson_decode($value, true);
            } catch (SimdJsonException $e) {
                throw new JsonException($e->getMessage(), $e->getCode(), $e);
            }
        } elseif (defined('JSON_THROW_ON_ERROR')) {
            // JSON_THROW_ON_ERROR is supported since PHP 7.3
            return json_decode($value, true, 512, JSON_THROW_ON_ERROR);
        } else {
            $decoded = json_decode($value, true);
            if ($decoded === null) {
                throw new UnexpectedValueException('Could not parse JSON: ' . json_last_error_msg(), json_last_error());
            }
            return $decoded;
        }
    }

    /**
     * @param string $value
     * @return array
     * @throws JsonException
     */
    public static function decodeArray($value)
    {
        $decoded = self::decode($value);
        if (!is_array($decoded)) {
            throw new UnexpectedValueException('JSON must be array type, get ' . gettype($decoded));
        }
        return $decoded;
    }

    /**
     * Check if string is valid JSON
     * @param string $value
     * @return bool
     */
    public static function isValid($value)
    {
        if (function_exists('simdjson_is_valid')) {
            return simdjson_is_valid($value);
        }

        try {
            self::decode($value);
            return true;
        } catch (Exception $e) {
            return false;
        }
    }
}
