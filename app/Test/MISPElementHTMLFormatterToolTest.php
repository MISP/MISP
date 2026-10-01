<?php
/**
 * MISPElementHTMLFormatterTool unit tests.
 *
 * Pure — no DB, no CakePHP bootstrap. The tool builds the inline HTML
 * that EventReport::replaceMISPElementByTheirValue() substitutes for
 * @[attribute](uuid) / @[object](uuid) / @[tag](name) references when a
 * report is exported through the convert_markdown_to_pdf module.
 *
 * Two properties are pinned here:
 *   - every formatter renders the element it was given (attribute() once
 *     shipped a template with hardcoded sample values and no placeholders,
 *     so every plain attribute reference in a PDF read "domain-ip /
 *     google.com" whatever the real indicator was), and
 *   - every interpolated field is HTML-escaped, so a value is data and
 *     can neither inject markup nor close the formatter's own spans.
 */

if (!function_exists('h')) {
    function h($text)
    {
        return htmlspecialchars((string)$text, ENT_QUOTES, 'UTF-8', true);
    }
}

require_once __DIR__ . '/../Lib/Tools/MISPElementHTMLFormatterTool.php';

use PHPUnit\Framework\TestCase;

class MISPElementHTMLFormatterToolTest extends TestCase
{
    const HOSTILE = 'V38 <i>x</i> & "dq" \'sq\' </span>';
    const HOSTILE_ESCAPED = 'V38 &lt;i&gt;x&lt;/i&gt; &amp; &quot;dq&quot; &#039;sq&#039; &lt;/span&gt;';

    /** @var MISPElementHTMLFormatterTool */
    private $tool;

    protected function setUp(): void
    {
        $this->tool = new MISPElementHTMLFormatterTool();
    }

    /**
     * The template must render the attribute it was given, not a sample.
     */
    public function testAttributeRendersTheRealTypeAndValue(): void
    {
        $html = $this->tool->attribute(['type' => 'ip-dst', 'value' => '203.0.113.88']);
        $this->assertStringContainsString('>ip-dst<', $html);
        $this->assertStringContainsString('>203.0.113.88<', $html);
        $this->assertStringNotContainsString('domain-ip', $html);
        $this->assertStringNotContainsString('google.com', $html);
    }

    public function testAttributeEscapesTypeAndValue(): void
    {
        $html = $this->tool->attribute(['type' => '<script>', 'value' => self::HOSTILE]);
        $this->assertStringContainsString('>&lt;script&gt;<', $html);
        $this->assertStringContainsString('>' . self::HOSTILE_ESCAPED . '<', $html);
        $this->assertSame(0, $this->countForeignTags($html));
    }

    public function testObjectAttributeEscapesAllThreeSinks(): void
    {
        $html = $this->tool->objectAttribute(
            ['name' => 'anno<b>tation'],
            ['object_relation' => 'te"xt', 'value' => self::HOSTILE]
        );
        $this->assertStringContainsString('>anno&lt;b&gt;tation ↦ <', $html);
        $this->assertStringContainsString('>te&quot;xt<', $html);
        $this->assertStringContainsString('>' . self::HOSTILE_ESCAPED . '<', $html);
        $this->assertSame(0, $this->countForeignTags($html));
    }

    public function testObjectEscapesNameAndFirstAttributeValue(): void
    {
        $html = $this->tool->object([
            'name' => 'anno<b>tation',
            'Attribute' => [['value' => self::HOSTILE], ['value' => 'second']],
        ]);
        $this->assertStringContainsString('>anno&lt;b&gt;tation<', $html);
        $this->assertStringContainsString('>' . self::HOSTILE_ESCAPED . '<', $html);
        $this->assertStringNotContainsString('second', $html);
        $this->assertSame(0, $this->countForeignTags($html));
    }

    public function testObjectWithoutAttributesUsesThePlaceholder(): void
    {
        $html = $this->tool->object(['name' => 'annotation', 'Attribute' => []]);
        $this->assertStringContainsString('>-- no attributes --<', $html);
        $html = $this->tool->object(['name' => 'annotation']);
        $this->assertStringContainsString('>-- no attributes --<', $html);
    }

    public function testTagEscapesColourAndName(): void
    {
        $html = $this->tool->tag(['name' => 'tlp:<amber>', 'colour' => '#FFC000" onload="x']);
        $this->assertStringContainsString('>tlp:&lt;amber&gt;<', $html);
        $this->assertStringContainsString('background-color: #FFC000&quot; onload=&quot;x;', $html);
        $this->assertStringNotContainsString('" onload="', $html);
        $this->assertSame(0, $this->countForeignTags($html));
    }

    public function testTagPicksTextColourFromBackground(): void
    {
        $dark = $this->tool->tag(['name' => 't', 'colour' => '#000000']);
        $light = $this->tool->tag(['name' => 't', 'colour' => '#FFFFFF']);
        $this->assertStringContainsString('color: white;', $dark);
        $this->assertStringContainsString('color: black;', $light);
    }

    /**
     * Every tag in the output must be one the template wrote itself: only
     * <span> and </span>. Anything else came in through a value.
     */
    private function countForeignTags(string $html): int
    {
        preg_match_all('/<\/?([a-z0-9]+)/i', $html, $m);
        return count(array_filter($m[1], function ($tag) {
            return strtolower($tag) !== 'span';
        }));
    }
}
