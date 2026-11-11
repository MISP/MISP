<?php
/**
 * CLICommonTrait::__term() unit tests.
 *
 * Pure — no DB, no CakePHP bootstrap. The trait is used by a small
 * harness class that exposes the private helper.
 *
 * __term() is the choke point that keeps database content from driving
 * the operator's terminal: every value the interactive CLI shell prints
 * is attacker-controlled (any perm_add user can store an attribute whose
 * value carries ESC[ sequences, and the core validator only rejects
 * values made entirely of control characters). C0 controls, DEL and the
 * C1 range are rewritten in cat -v caret notation, tab and newlines
 * become spaces, and the Unicode bidi overrides are spelled out.
 * Printable text, including non-ASCII, must pass through unchanged.
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Console/Command/CLIShell/cli_common.php';

class CLIShellTerminalSanitiserHarness
{
    use CLICommonTrait;

    public $__user = [];
    public $__entityConfig = [];
    public $__perPage = 20;
    public $__maxPerPage = 1000;

    public function term($value)
    {
        return $this->__term($value);
    }

    public function termRows(array $rows)
    {
        return $this->__termRows($rows);
    }
}

class CLIShellTerminalSanitiserTest extends TestCase
{
    /** @var CLIShellTerminalSanitiserHarness */
    private $shell;

    protected function setUp(): void
    {
        $this->shell = new CLIShellTerminalSanitiserHarness();
    }

    public function testEscapeSequencesBecomeCaretNotation(): void
    {
        $this->assertSame(
            '^[[2J^[[H*** FAKE ***^[]0;pwned^Gtail',
            $this->shell->term("\x1b[2J\x1b[H*** FAKE ***\x1b]0;pwned\x07tail")
        );
    }

    public function testEveryC0ControlAndDelIsRewritten(): void
    {
        for ($cp = 0; $cp < 0x20; $cp++) {
            if (in_array($cp, [0x09, 0x0A, 0x0D], true)) {
                continue;
            }
            $this->assertSame(
                'a^' . chr($cp + 0x40) . 'b',
                $this->shell->term('a' . chr($cp) . 'b'),
                sprintf('code point 0x%02X', $cp)
            );
        }
        $this->assertSame('a^?b', $this->shell->term("a\x7fb"));
    }

    public function testC1ControlsAreRewrittenNotDeletedFromUtf8(): void
    {
        // U+009B is the 8-bit CSI; encoded as C2 9B in UTF-8.
        $this->assertSame('M-^[31mC1', $this->shell->term("\u{9B}31mC1"));
        // U+0085 (NEL) sits in the same range.
        $this->assertSame('xM-^Ey', $this->shell->term("x\u{85}y"));
    }

    public function testTabAndNewlinesBecomeSpaces(): void
    {
        $this->assertSame('a b c d', $this->shell->term("a\tb\nc\rd"));
    }

    public function testBidiOverridesAndIsolatesAreSpelledOut(): void
    {
        $this->assertSame(
            'google.com <U+202E>moc.elgoog',
            $this->shell->term("google.com \u{202E}moc.elgoog")
        );
        foreach ([0x202A, 0x202B, 0x202C, 0x202D, 0x2066, 0x2067, 0x2068, 0x2069] as $cp) {
            $this->assertSame(
                sprintf('<U+%04X>', $cp),
                $this->shell->term(mb_chr($cp, 'UTF-8')),
                sprintf('U+%04X', $cp)
            );
        }
    }

    public function testPrintableTextPassesThroughUnchanged(): void
    {
        $samples = [
            'plain ascii 123',
            "caf\u{E9} \u{A9} \u{2192} \u{6F22}\u{5B57} \u{270E} \u{2500}",
            '<error>markup is data, not styling</error>',
            'v31-e7209-o1.example',
            '',
        ];
        foreach ($samples as $sample) {
            $this->assertSame($sample, $this->shell->term($sample), $sample);
        }
        $this->assertNull($this->shell->term(null));
        $this->assertSame(42, $this->shell->term(42));
    }

    public function testInvalidUtf8FallsBackToByteLevelC0Strip(): void
    {
        // A lone 0xFF is not UTF-8, so the code-point pass fails and the
        // byte-level pass still neutralises the escape.
        $this->assertSame("\xff^[[1mX", $this->shell->term("\xff\x1b[1mX"));
    }

    public function testArraysAreMappedRecursively(): void
    {
        $this->assertSame(
            ['a^Gb', ['^[c']],
            $this->shell->term(["a\x07b", ["\x1bc"]])
        );
    }

    public function testRowsAreSanitisedCellByCell(): void
    {
        $rows = [
            ['id' => 5, 'value' => "\x1b[2Jx", 'nested' => ["\x07"]],
        ];
        $this->assertSame(
            [['id' => 5, 'value' => '^[[2Jx', 'nested' => ["\x07"]]],
            $this->shell->termRows($rows)
        );
    }
}
