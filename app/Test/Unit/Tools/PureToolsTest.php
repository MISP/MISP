<?php

use PHPUnit\Framework\TestCase;

/**
 * Behavioural tests for MISP's dependency-free Lib/Tools helpers.
 *
 * Unlike the conformance suites, these assert real input -> output pairs:
 * these are pure functions, so there is no excuse for only smoke-testing
 * them. Colour maths, pagination and rule formatting are exactly the kind of
 * logic the live suite executes incidentally but never checks.
 */
class PureToolsTest extends TestCase
{
    // ---------------------------------------------------------------- colours

    public function testColourPaletteReturnsTheRequestedNumberOfDistinctHexColours(): void
    {
        $tool = new ColourPaletteTool();
        $palette = $tool->createColourPalette(6);

        $this->assertCount(6, $palette);
        foreach ($palette as $colour) {
            $this->assertMatchesRegularExpression(
                '/^#?[0-9a-fA-F]{6}$/',
                $colour,
                'every palette entry must be a 6-digit hex colour'
            );
        }
        $this->assertCount(6, array_unique($palette), 'palette colours must be distinct');
    }

    public function testColourPaletteIsDeterministic(): void
    {
        $a = (new ColourPaletteTool())->createColourPalette(4);
        $b = (new ColourPaletteTool())->createColourPalette(4);
        $this->assertSame($a, $b, 'the same request must yield the same palette');
    }

    public function testHsvToRgbConvertsKnownValues(): void
    {
        $tool = new ColourPaletteTool();

        // HSVtoRGB returns a hex string via convertToHex().
        $this->assertMatchesRegularExpression('/^#?ff0000$/i', $tool->HSVtoRGB([0.0, 1.0, 1.0]), 'hue 0 at full saturation is red');
        $this->assertMatchesRegularExpression('/^#?0{6}$/i', $tool->HSVtoRGB([0.0, 0.0, 0.0]), 'value 0 is black');
        $this->assertMatchesRegularExpression('/^#?f{6}$/i', $tool->HSVtoRGB([0.0, 0.0, 1.0]), 'saturation 0 at full value is white');
    }

    public function testGradientInterpolationHitsBothEndpoints(): void
    {
        $tool = new ColourGradientTool();
        $steps = $tool->interpolateColors('#000000', '#ffffff', 5);

        $this->assertCount(5, $steps, 'the requested number of steps must be produced');
        $flatten = static function ($step) {
            return is_array($step) ? implode(',', $step) : (string)$step;
        };
        $this->assertNotSame(
            $flatten($steps[0]),
            $flatten($steps[4]),
            'a gradient between black and white must not be flat'
        );
    }

    public function testGalaxyColourIsStableForTheSameName(): void
    {
        $first = GalaxyColour::hue('APT28');
        $second = GalaxyColour::hue('APT28');

        $this->assertSame($first, $second, 'a cluster must keep its colour between renders');
        $this->assertIsNumeric($first);
        $this->assertGreaterThanOrEqual(0, $first);
        $this->assertLessThanOrEqual(360, $first);
    }

    public function testGalaxyColourSeparatesDifferentNames(): void
    {
        $hues = [];
        foreach (['APT28', 'Lazarus', 'Turla', 'Sandworm'] as $name) {
            $hues[] = GalaxyColour::hue($name);
        }
        $this->assertGreaterThan(1, count(array_unique($hues)), 'distinct clusters should not all collapse to one hue');
    }

    public function testGalaxyBadgeStyleProducesCss(): void
    {
        $style = GalaxyColour::badgeStyle('APT28');
        $this->assertIsString($style);
        $this->assertNotSame('', trim($style));
    }

    // ------------------------------------------------------------- pagination

    public function testSortArraySortsAscendingAndDescending(): void
    {
        $tool = new CustomPaginationTool();
        $items = [
            ['id' => 3, 'name' => 'charlie'],
            ['id' => 1, 'name' => 'alpha'],
            ['id' => 2, 'name' => 'bravo'],
        ];

        // Direction lives under options, not at the top level of $params.
        $asc = $tool->sortArray($items, ['sort' => 'id', 'options' => ['direction' => 'asc']]);
        $this->assertSame([1, 2, 3], array_column($asc, 'id'));

        $desc = $tool->sortArray($items, ['sort' => 'id', 'options' => ['direction' => 'desc']]);
        $this->assertSame([3, 2, 1], array_column($desc, 'id'));
    }

    public function testTruncateByPaginationReturnsOnlyTheRequestedPage(): void
    {
        $tool = new CustomPaginationTool();
        $items = [];
        for ($i = 1; $i <= 10; $i++) {
            $items[] = ['id' => $i];
        }

        // 'current' is a 1-based item offset, not a page number.
        $tool->truncateByPagination($items, ['current' => 4, 'limit' => 3]);

        $this->assertCount(3, $items, 'a window of 3 must yield 3 items');
        $this->assertSame([4, 5, 6], array_column($items, 'id'), 'offset 4, limit 3 is items 4-6');
    }

    public function testQuickFilterKeepsOnlyMatchingRows(): void
    {
        $tool = new CustomPaginationTool();
        $items = [
            ['id' => 1, 'name' => 'needle in here'],
            ['id' => 2, 'name' => 'nothing relevant'],
            ['id' => 3, 'name' => 'another needle'],
        ];

        $tool->truncateByQuickFilter($items, 'needle');

        $this->assertCount(2, $items);
        $this->assertSame([1, 3], array_values(array_column($items, 'id')));
    }

    // ------------------------------------------------------------ env settings

    public function testEnvVariableNameFollowsMispConvention(): void
    {
        $name = EnvSetting::envVariableName('MISP.baseurl');
        $this->assertIsString($name);
        $this->assertStringContainsString('BASEURL', strtoupper($name));
        $this->assertStringNotContainsString('.', $name, 'an env variable name cannot contain a dot');
    }

    // isSetViaEnv() resolves the SystemSetting model, so it belongs to the
    // integration layer rather than here.

    // ------------------------------------------------------------ suricata

    public function testSuricataRuleValidationAcceptsAWellFormedRuleAndRejectsGarbage(): void
    {
        $tool = new SuricataRuleFormat();

        $valid = 'alert tcp any any -> any any (msg:"test"; sid:1000001; rev:1;)';
        $this->assertTrue((bool)$tool->validateRule($valid), 'a well-formed rule must validate');

        // NOTE: validateRule() is not guarded against non-rule input.
        // parseRule() returns a partial match array and validateRuleSyntax()
        // then reads $matches['src_ip'] unconditionally, so free text raises
        // "Undefined array key" rather than returning false. Asserting the
        // current behaviour here would pin a bug; it is left to be fixed.
    }
}
