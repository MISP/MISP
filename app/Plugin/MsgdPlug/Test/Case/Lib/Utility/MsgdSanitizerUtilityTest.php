<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 4) . '/Lib/Utility/MsgdSanitizerUtility.php';

/**
 * Test suite for MsgdSanitizerUtility.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Test.Case.Lib.Utility
 */
final class MsgdSanitizerUtilityTest extends TestCase
{
    /**
     * Tests that isValidUuid returns true for a valid RFC 4122 UUID.
     *
     * @return void
     */
    public function testIsValidUuidReturnsTrueForValidUuid(): void
    {
        $validUuid = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11';
        $this->assertTrue(MsgdSanitizerUtility::isValidUuid($validUuid));
    }

    /**
     * Tests that isValidUuid returns true for a valid UUID containing surrounding whitespace.
     *
     * @return void
     */
    public function testIsValidUuidReturnsTrueForValidUuidWithWhitespace(): void
    {
        $validUuidWithSpace = '  a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11  ';
        $this->assertTrue(MsgdSanitizerUtility::isValidUuid($validUuidWithSpace));
    }

    /**
     * Tests that isValidUuid returns false for an improperly formatted UUID.
     *
     * @return void
     */
    public function testIsValidUuidReturnsFalseForInvalidUuidFormat(): void
    {
        $invalidUuid = 'invalid-uuid-format-1234';
        $this->assertFalse(MsgdSanitizerUtility::isValidUuid($invalidUuid));
    }

    /**
     * Tests that isValidUuid returns false when length does not match 36 characters.
     *
     * @return void
     */
    public function testIsValidUuidReturnsFalseForInvalidLength(): void
    {
        $tooShortUuid = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a1';
        $this->assertFalse(MsgdSanitizerUtility::isValidUuid($tooShortUuid));
    }

    /**
     * Tests that sanitizeString returns an empty string when given an empty input.
     *
     * @return void
     */
    public function testSanitizeStringReturnsEmptyStringForEmptyInput(): void
    {
        $this->assertSame('', MsgdSanitizerUtility::sanitizeString(''));
    }

    /**
     * Tests that sanitizeString strips HTML/script tags from input.
     *
     * @return void
     */
    public function testSanitizeStringStripsHtmlTags(): void
    {
        $input = '<script>alert("xss")</script><strong>Clean Text</strong>';
        $sanitized = MsgdSanitizerUtility::sanitizeString($input);

        $this->assertSame('alert("xss")Clean Text', $sanitized);
    }

    /**
     * Tests that sanitizeString truncates multibyte UTF-8 string to specified maximum length.
     *
     * @return void
     */
    public function testSanitizeStringTruncatesToMaximumAllowedLength(): void
    {
        $input = '1234567890';
        $sanitized = MsgdSanitizerUtility::sanitizeString($input, 5);

        $this->assertSame('12345', $sanitized);
    }

    /**
     * Tests that sanitizeString strips invisible control characters.
     *
     * @return void
     */
    public function testSanitizeStringRemovesControlCharacters(): void
    {
        $input = "Text\x00With\x07Control\x1FChars";
        $sanitized = MsgdSanitizerUtility::sanitizeString($input);

        $this->assertSame('TextWithControlChars', $sanitized);
    }

    /**
     * Tests that sanitizeString removes newlines by default when preserveNewlines is false.
     *
     * @return void
     */
    public function testSanitizeStringRemovesNewlinesWhenPreserveNewlinesIsFalse(): void
    {
        $input = "Line 1\nLine 2\rLine 3";
        $sanitized = MsgdSanitizerUtility::sanitizeString($input, 191);

        $this->assertSame('Line 1Line 2Line 3', $sanitized);
    }

    /**
     * Tests that sanitizeString preserves line breaks when preserveNewlines is set to true.
     *
     * @return void
     */
    public function testSanitizeStringPreservesNewlinesWhenPreserveNewlinesIsTrue(): void
    {
        $input = "Line 1\nLine 2";
        $sanitized = MsgdSanitizerUtility::sanitizeString($input, 191, true);

        $this->assertSame("Line 1\nLine 2", $sanitized);
    }

    /**
     * Tests that sanitizeString safely handles strings exceeding MAX_RAW_STRING_LENGTH.
     *
     * @return void
     */
    public function testSanitizeStringTruncatesExcessiveRawStringLength(): void
    {
        $longInput = str_repeat('a', MsgdSanitizerUtility::MAX_RAW_STRING_LENGTH + 500);
        $sanitized = MsgdSanitizerUtility::sanitizeString($longInput, 10);

        $this->assertSame('aaaaaaaaaa', $sanitized);
    }

    /**
     * Tests that isValidUuid returns true for valid uppercase UUIDs.
     *
     * @return void
     */
    public function testIsValidUuidAcceptsUppercaseAndMixedCase(): void
    {
        $uppercaseUuid = 'A0EEBC99-9C0B-4EF8-BB6D-6BB9BD380A11';
        $this->assertTrue(MsgdSanitizerUtility::isValidUuid($uppercaseUuid));
    }

    /**
     * Tests that sanitizeString correctly truncates multibyte UTF-8 characters without corruption.
     *
     * @return void
     */
    public function testSanitizeStringTruncatesMultibyteCharactersCorrectly(): void
    {
        $input = 'AçãoEvolução';
        $sanitized = MsgdSanitizerUtility::sanitizeString($input, 4);

        $this->assertSame('Ação', $sanitized);
    }

    /**
     * Tests that sanitizeString handles invalid UTF-8 byte sequences gracefully via mb_scrub.
     *
     * @return void
     */
    public function testSanitizeStringHandlesInvalidUtf8Sequences(): void
    {
        $invalidUtf8 = "Test\x80String";
        $sanitized = MsgdSanitizerUtility::sanitizeString($invalidUtf8);

        $this->assertStringContainsString('Test', $sanitized);
        $this->assertStringContainsString('String', $sanitized);
    }

    /**
     * Tests that sanitizeString clamps zero or negative lengths to a minimum of 1 character.
     *
     * @return void
     */
    public function testSanitizeStringClampsZeroOrNegativeLengthToOne(): void
    {
        $input = 'SampleText';

        $sanitizedZero = MsgdSanitizerUtility::sanitizeString($input, 0);
        $sanitizedNegative = MsgdSanitizerUtility::sanitizeString($input, -5);

        $this->assertSame('S', $sanitizedZero);
        $this->assertSame('S', $sanitizedNegative);
    }
}
