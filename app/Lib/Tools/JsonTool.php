<?php
class JsonTool
{
    /**
     * @param mixed $value
     * @param bool $prettyPrint
     * @param bool $appendNewLine Add new line char to end of encoded string
     * @param bool $invalidUtf8Substitute Convert invalid UTF-8 characters to \0xfffd
     * @returns string
     * @throws JsonException
     */
    public static function encode($value, $prettyPrint = false, $appendNewLine = false, $invalidUtf8Substitute = false)
    {
        if (function_exists('simdjson_encode')) {
            // Use faster version of json_encode from simdjson PHP extension if this extension is installed
            $flags = $prettyPrint ? SIMDJSON_PRETTY_PRINT : 0;
            if ($appendNewLine) {
                $flags |= SIMDJSON_APPEND_NEWLINE;
            }
            if ($invalidUtf8Substitute) {
                $flags |= SIMDJSON_INVALID_UTF8_SUBSTITUTE;
            }
            try {
                return simdjson_encode($value, $flags);
            } catch (SimdJsonException $e) {
                throw new JsonException($e->getMessage(), $e->getCode(), $e);
            }
        }

        $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR;
        if ($prettyPrint) {
            $flags |= JSON_PRETTY_PRINT;
        }
        if ($invalidUtf8Substitute) {
            $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
        }
        $output = json_encode($value, $flags);
        return $appendNewLine ? ($output . "\n") : $output;
    }

    /**
     * @param string $value
     * @return SimdJsonBase64Encode|string
     */
    public static function base64Encode(string $value)
    {
        if (class_exists('SimdJsonBase64Encode')) {
            return new SimdJsonBase64Encode($value);
        }
        return base64_encode($value);
    }

    /**
     * Encode big array to tmp file to reduce memory usage
     *
     * @param array $list
     * @return TmpFileTool
     * @throws JsonException
     * @throws Exception
     */
    public static function encodeBigArray(array $list)
    {
        $output = new TmpFileTool();

        if (function_exists('simdjson_encode_to_stream')) {
            simdjson_encode_to_stream($list, $output->resource());
        } else {
            $output->write('[');
            foreach ($list as $item) {
                $output->writeWithSeparator(JsonTool::encode($item), ',');
            }
            $output->write(']');
        }

        return $output;
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
        }
        return json_decode($value, true, 512, JSON_THROW_ON_ERROR);
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

        if (function_exists('json_validate')) {
            return json_validate($value);
        }

        try {
            self::decode($value);
            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * JSON supports just unicode strings. This helper method converts non unicode chars to Unicode Replacement Character U+FFFD (UTF-8)
     * @param string $string
     * @return string
     */
    public static function escapeNonUnicode($string)
    {
        if ((function_exists('simdjson_is_valid_utf8') && simdjson_is_valid_utf8($string)) || mb_check_encoding($string, 'UTF-8')) {
            return $string; // string is valid unicode
        }

        return htmlspecialchars_decode(htmlspecialchars($string, ENT_SUBSTITUTE, 'UTF-8'));
    }

    /**
     * Convert all integers in array or object to strings. Useful for php7.4 to php8 migration
     * @param mixed $data
     */
    public static function convertIntegersToStrings(&$data)
    {
        if (is_array($data)) {
            foreach ($data as &$value) {
                if (is_int($value)) {
                    $value = strval($value);
                } elseif (is_array($value) || is_object($value)) {
                    JsonTool::convertIntegersToStrings($value);
                }
            }
        }
    }
}
