<?php
/**
 * Galaxy icon name validation (A42).
 *
 * A galaxy's icon field reaches the correlation graph as a class token, and
 * both graph scripts once concatenated it into markup. The model now accepts
 * only Font Awesome icon names. Pure PHPUnit, no CakePHP bootstrap: the
 * framework classes Galaxy.php needs at load time are stubbed here, and the
 * validation rule is read from the class defaults without instantiating it.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}

if (!class_exists('AppModel', false)) {
    class AppModel
    {
    }
}

require_once __DIR__ . '/../Model/Galaxy.php';

class GalaxyIconNameTest extends \PHPUnit\Framework\TestCase
{
    const REPORTED_PAYLOAD = 'x"></i><img src=x onerror="alert(location.href)"><i class="x';

    public function testAcceptsIconNamesAndTheEmptyIcon()
    {
        foreach (['globe', 'user-secret', 'shield-alt', '500px', ''] as $icon) {
            $this->assertTrue(Galaxy::isValidIconName($icon), $icon);
        }
    }

    public function testRefusesAnythingOutsideTheIconAlphabet()
    {
        $refused = [
            self::REPORTED_PAYLOAD,
            '"><img src=x onerror=alert(1)>',
            'fa globe',
            "x'y",
            'a<b',
            'Globe',
            'globe/',
        ];
        foreach ($refused as $icon) {
            $this->assertFalse(Galaxy::isValidIconName($icon), $icon);
        }
        $this->assertFalse(Galaxy::isValidIconName(null));
        $this->assertFalse(Galaxy::isValidIconName(['globe']));
    }

    public function testTheModelValidatesTheIconWithTheSameRule()
    {
        $defaults = (new ReflectionClass('Galaxy'))->getDefaultProperties();
        $this->assertArrayHasKey('icon', $defaults['validate']);
        $rule = $defaults['validate']['icon']['iconName'];
        $this->assertSame(['custom', Galaxy::ICON_NAME_PATTERN], $rule['rule']);
        $this->assertTrue($rule['allowEmpty']);
        // What Validation::custom() will do with the rule
        $this->assertSame(0, preg_match($rule['rule'][1], self::REPORTED_PAYLOAD));
        $this->assertSame(1, preg_match($rule['rule'][1], 'globe'));
    }

    public function testEveryShippedGalaxyIconStillPasses()
    {
        $files = glob(__DIR__ . '/../files/misp-galaxy/galaxies/*.json');
        if (empty($files)) {
            $this->markTestSkipped('misp-galaxy submodule not checked out');
        }
        $seen = 0;
        foreach ($files as $file) {
            $galaxy = json_decode(file_get_contents($file), true);
            if (!isset($galaxy['icon'])) {
                continue;
            }
            $seen++;
            $this->assertTrue(Galaxy::isValidIconName($galaxy['icon']), basename($file) . ': ' . $galaxy['icon']);
        }
        $this->assertGreaterThan(0, $seen);
    }
}
