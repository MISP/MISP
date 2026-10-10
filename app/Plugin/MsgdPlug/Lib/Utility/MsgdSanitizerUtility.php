<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

/**
 * Utility for input sanitization.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Lib.Utility
 */
final class MsgdSanitizerUtility
{
    /**
     * Pattern for RFC 4122 UUID validation.
     */
    public const UUID_REGEX = '/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i';

    /**
     * Default maximum length for name fields.
     */
    public const MAX_NAME_LENGTH = 191;

    /**
     * Maximum allowed raw string length before processing.
     */
    public const MAX_RAW_STRING_LENGTH = 65535;

    /**
     * Checks if a string is a valid RFC 4122 UUID.
     *
     * @param string $uuidCandidate
     *
     * @return bool
     */
    public static function isValidUuid(string $uuidCandidate): bool
    {
        $trimmedCandidate = trim($uuidCandidate);

        if (strlen($trimmedCandidate) !== 36) {
            return false;
        }

        return (bool)preg_match(self::UUID_REGEX, $trimmedCandidate);
    }

    /**
     * Cleans control characters and trims a string to a safe length.
     *
     * @param string $rawInputString
     * @param int $maximumAllowedLength
     * @param bool $preserveNewlines
     *
     * @return string
     */
    public static function sanitizeString(
        string $rawInputString,
        int $maximumAllowedLength = self::MAX_NAME_LENGTH,
        bool $preserveNewlines = false
    ): string {
        if ($rawInputString === '') {
            return '';
        }

        if (strlen($rawInputString) > self::MAX_RAW_STRING_LENGTH) {
            $rawInputString = substr($rawInputString, 0, self::MAX_RAW_STRING_LENGTH);
        }

        $validUtf8String = mb_scrub($rawInputString, 'UTF-8');

        if (class_exists('Normalizer')) {
            $normalizedString = Normalizer::normalize($validUtf8String);
            if (is_string($normalizedString)) {
                $validUtf8String = $normalizedString;
            }
        }

        $noHtmlString = strip_tags($validUtf8String);

        $pattern = $preserveNewlines
            ? '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]|\p{Cf}/u'
            : '/\p{C}/u';

        $cleanedString = (string)preg_replace($pattern, '', $noHtmlString);
        $trimmedString = trim($cleanedString);

        return mb_substr($trimmedString, 0, max(1, $maximumAllowedLength), 'UTF-8');
    }
}
