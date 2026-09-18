<?php
/**
 * EventTemplateInfoRenderer unit tests.
 *
 * Pure — no DB, no CakePHP bootstrap. The renderer is a thin
 * regex-substitution shim; these tests exercise every branch:
 *
 *   - the four supported variables ({{date}}, {{now}}, {{user}},
 *     {{field:<id>}}),
 *   - date/now context overrides (for deterministic assertions),
 *   - {{field:<id>}} against scalars, arrays (first-value
 *     semantics), nulls, missing ids, and numeric values,
 *   - repeated occurrences of the same variable,
 *   - malformed {{...}} sequences passing through unchanged,
 *   - non-string template inputs yielding an empty string.
 */

require_once __DIR__ . '/../Lib/Tools/EventTemplateInfoRenderer.php';

use PHPUnit\Framework\TestCase;

class EventTemplateInfoRendererTest extends TestCase
{
    /** @var EventTemplateInfoRenderer */
    private $renderer;

    protected function setUp(): void
    {
        $this->renderer = new EventTemplateInfoRenderer();
    }

    public function testEmptyTemplateReturnsEmptyString(): void
    {
        $this->assertSame('', $this->renderer->render(''));
    }

    public function testNonStringTemplateReturnsEmptyString(): void
    {
        $this->assertSame('', $this->renderer->render(null));
        $this->assertSame('', $this->renderer->render(42));
    }

    public function testPassthroughWhenNoVariables(): void
    {
        $this->assertSame(
            'Plain text, no vars.',
            $this->renderer->render('Plain text, no vars.')
        );
    }

    public function testDateVariableUsesContextOverride(): void
    {
        $out = $this->renderer->render(
            'On {{date}}.',
            array(),
            array('date' => '2026-04-23')
        );
        $this->assertSame('On 2026-04-23.', $out);
    }

    public function testDateVariableFallsBackToTodayWhenNoContext(): void
    {
        $out = $this->renderer->render('Today: {{date}}');
        $this->assertMatchesRegularExpression('/^Today: \d{4}-\d{2}-\d{2}$/', $out);
    }

    public function testNowVariableUsesContextOverride(): void
    {
        $out = $this->renderer->render(
            'At {{now}}.',
            array(),
            array('now' => '2026-04-23T12:34:56+00:00')
        );
        $this->assertSame('At 2026-04-23T12:34:56+00:00.', $out);
    }

    public function testNowVariableFallsBackToIso8601WhenNoContext(): void
    {
        $out = $this->renderer->render('At {{now}}');
        // ISO-8601 with timezone offset: 2026-04-23T12:34:56+02:00
        $this->assertMatchesRegularExpression(
            '/^At \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+\-]\d{2}:\d{2}$/',
            $out
        );
    }

    public function testUserVariable(): void
    {
        $out = $this->renderer->render(
            'By {{user}}.',
            array(),
            array('user' => 'alice@example.org')
        );
        $this->assertSame('By alice@example.org.', $out);
    }

    public function testUserVariableEmptyWhenNoContext(): void
    {
        $out = $this->renderer->render('By {{user}}.');
        $this->assertSame('By .', $out);
    }

    public function testFieldVariableScalar(): void
    {
        $out = $this->renderer->render(
            'From {{field:sender}}.',
            array('sender' => 'bad@example.com')
        );
        $this->assertSame('From bad@example.com.', $out);
    }

    public function testFieldVariableUsesFirstArrayEntry(): void
    {
        // Repeatable / multi-valued fields arrive as arrays; the renderer
        // takes the first value only (PRD §7.1).
        $out = $this->renderer->render(
            'First: {{field:recipients}}',
            array('recipients' => array('first@x', 'second@x', 'third@x'))
        );
        $this->assertSame('First: first@x', $out);
    }

    public function testFieldVariableEmptyArrayYieldsEmptyString(): void
    {
        $out = $this->renderer->render(
            '[{{field:recipients}}]',
            array('recipients' => array())
        );
        $this->assertSame('[]', $out);
    }

    public function testFieldVariableNullYieldsEmptyString(): void
    {
        $out = $this->renderer->render(
            '[{{field:sender}}]',
            array('sender' => null)
        );
        $this->assertSame('[]', $out);
    }

    public function testFieldVariableMissingKeyYieldsEmptyString(): void
    {
        $out = $this->renderer->render(
            '[{{field:sender}}]',
            array()
        );
        $this->assertSame('[]', $out);
    }

    public function testFieldVariableIntValueIsStringified(): void
    {
        $out = $this->renderer->render(
            'Score {{field:score}}',
            array('score' => 42)
        );
        $this->assertSame('Score 42', $out);
    }

    public function testRepeatedVariableOccurrencesAreAllReplaced(): void
    {
        $out = $this->renderer->render(
            '{{user}} ({{user}})',
            array(),
            array('user' => 'alice@x')
        );
        $this->assertSame('alice@x (alice@x)', $out);
    }

    public function testMalformedSequencePassesThroughUnchanged(): void
    {
        // Unknown bare identifier inside {{...}} — not matched by the
        // renderer's regex, so it's left in place. (EventTemplateValidator
        // rejects this shape at save time; the renderer stays permissive
        // so stale templates don't crash at instantiation.)
        $out = $this->renderer->render('Hi {{nonsense}}.');
        $this->assertSame('Hi {{nonsense}}.', $out);
    }

    public function testSingleBraceIsLeftAlone(): void
    {
        $out = $this->renderer->render('Price: {5.99}');
        $this->assertSame('Price: {5.99}', $out);
    }

    public function testMixedVariablesInOneTemplate(): void
    {
        $out = $this->renderer->render(
            'Spearphishing — {{date}} — {{field:sender}} — by {{user}}',
            array('sender' => 'bad@x.com'),
            array('date' => '2026-04-23', 'user' => 'analyst@y.com')
        );
        $this->assertSame(
            'Spearphishing — 2026-04-23 — bad@x.com — by analyst@y.com',
            $out
        );
    }
}
