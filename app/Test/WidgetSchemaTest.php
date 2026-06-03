<?php
/**
 * WidgetSchema contract unit tests (PRD §5.7).
 *
 * Pure PHPUnit — follows the convention used by every other test
 * under app/Test/: no CakePHP bootstrap, no DB. WidgetSchema has no
 * framework dependencies (it's a pure data-shape validator) so no
 * stubs are needed.
 */

require_once __DIR__ . '/../Vendor/autoload.php';
require_once __DIR__ . '/../Lib/Dashboard/Tools/WidgetSchema.php';

use PHPUnit\Framework\TestCase;

class WidgetSchemaTest extends TestCase
{
    // -------- getSchema() --------

    public function testGetSchemaReturnsArrayWhenWidgetDeclaresIt(): void
    {
        $widget = new stdClass();
        $widget->schema = ['window' => ['type' => 'time_window']];
        $this->assertSame(
            ['window' => ['type' => 'time_window']],
            WidgetSchema::getSchema($widget)
        );
    }

    public function testGetSchemaReturnsEmptyArrayForWidgetWithoutSchema(): void
    {
        $widget = new stdClass();
        $this->assertSame([], WidgetSchema::getSchema($widget));
    }

    public function testGetSchemaReturnsEmptyArrayWhenSchemaIsNonArray(): void
    {
        $widget = new stdClass();
        $widget->schema = 'not an array';
        $this->assertSame([], WidgetSchema::getSchema($widget));
    }

    public function testGetSchemaReturnsEmptyArrayForNonObjectInput(): void
    {
        $this->assertSame([], WidgetSchema::getSchema(null));
        $this->assertSame([], WidgetSchema::getSchema('Foo'));
        $this->assertSame([], WidgetSchema::getSchema(['type' => 'time_window']));
    }

    public function testGetSchemaReturnsEmptyArrayForExplicitEmptyDeclaration(): void
    {
        $widget = new stdClass();
        $widget->schema = [];
        $this->assertSame([], WidgetSchema::getSchema($widget));
    }

    // -------- validate() happy paths --------

    public function testValidateAcceptsEmptySchema(): void
    {
        $this->assertNull(WidgetSchema::validate([]));
    }

    public function testValidateAcceptsAllCanonicalTypes(): void
    {
        $schema = [];
        foreach (WidgetSchema::CANONICAL_TYPES as $type) {
            $schema['p_' . $type] = ['type' => $type];
        }
        // enum requires extra structure; not present here because it's
        // scalar, not canonical.
        $this->assertNull(WidgetSchema::validate($schema));
    }

    public function testValidateAcceptsScalarTypes(): void
    {
        $schema = [
            's' => ['type' => 'string'],
            'i' => ['type' => 'int'],
            'b' => ['type' => 'bool'],
            'e' => ['type' => 'enum', 'enum' => ['a', 'b']],
        ];
        $this->assertNull(WidgetSchema::validate($schema));
    }

    public function testValidateAcceptsAllOptionalFields(): void
    {
        $schema = [
            'window' => [
                'type'     => 'time_window',
                'default'  => 'P7D',
                'help'     => 'Time window to aggregate over',
                'required' => false,
            ],
        ];
        $this->assertNull(WidgetSchema::validate($schema));
    }

    public function testValidateIgnoresUnknownEntryKeysForwardCompat(): void
    {
        $schema = [
            'window' => [
                'type'           => 'time_window',
                'future_field'   => 'some value',
                'another_future' => ['nested'],
            ],
        ];
        $this->assertNull(WidgetSchema::validate($schema));
    }

    // -------- validate() failures --------

    public function testValidateRejectsNonArraySchema(): void
    {
        $errors = WidgetSchema::validate('not an array');
        $this->assertIsArray($errors);
        $this->assertArrayHasKey('_schema', $errors);
    }

    public function testValidateRejectsEntryWithoutType(): void
    {
        $errors = WidgetSchema::validate([
            'window' => ['default' => 'P7D'],
        ]);
        $this->assertIsArray($errors);
        $this->assertArrayHasKey('window', $errors);
        $this->assertStringContainsString('type', $errors['window']);
    }

    public function testValidateRejectsUnknownType(): void
    {
        $errors = WidgetSchema::validate([
            'window' => ['type' => 'made_up_type'],
        ]);
        $this->assertIsArray($errors);
        $this->assertArrayHasKey('window', $errors);
        $this->assertStringContainsString('made_up_type', $errors['window']);
    }

    public function testValidateRejectsEnumWithoutEnumArray(): void
    {
        $errors = WidgetSchema::validate([
            'level' => ['type' => 'enum'],
        ]);
        $this->assertIsArray($errors);
        $this->assertArrayHasKey('level', $errors);
        $this->assertStringContainsString('enum', $errors['level']);
    }

    public function testValidateRejectsEnumWithEmptyEnumArray(): void
    {
        $errors = WidgetSchema::validate([
            'level' => ['type' => 'enum', 'enum' => []],
        ]);
        $this->assertIsArray($errors);
        $this->assertArrayHasKey('level', $errors);
    }

    public function testValidateRejectsEnumWithNonArrayEnum(): void
    {
        $errors = WidgetSchema::validate([
            'level' => ['type' => 'enum', 'enum' => 'a,b,c'],
        ]);
        $this->assertIsArray($errors);
        $this->assertArrayHasKey('level', $errors);
    }

    public function testValidateRejectsRequiredNotBoolean(): void
    {
        $errors = WidgetSchema::validate([
            'window' => ['type' => 'time_window', 'required' => 'yes'],
        ]);
        $this->assertIsArray($errors);
        $this->assertArrayHasKey('window', $errors);
        $this->assertStringContainsString('required', $errors['window']);
    }

    public function testValidateRejectsHelpNotString(): void
    {
        $errors = WidgetSchema::validate([
            'window' => ['type' => 'time_window', 'help' => ['not', 'a', 'string']],
        ]);
        $this->assertIsArray($errors);
        $this->assertArrayHasKey('window', $errors);
        $this->assertStringContainsString('help', $errors['window']);
    }

    public function testValidateRejectsNumericKey(): void
    {
        $errors = WidgetSchema::validate([
            0 => ['type' => 'time_window'],
        ]);
        $this->assertIsArray($errors);
        $this->assertArrayHasKey('_keys', $errors);
    }

    public function testValidateRejectsNonArrayEntry(): void
    {
        $errors = WidgetSchema::validate([
            'window' => 'time_window',
        ]);
        $this->assertIsArray($errors);
        $this->assertArrayHasKey('window', $errors);
    }

    public function testValidateAccumulatesMultipleErrors(): void
    {
        $errors = WidgetSchema::validate([
            'a' => ['type' => 'unknown_type'],
            'b' => ['default' => 'no type here'],
            'c' => ['type' => 'enum'],
        ]);
        $this->assertIsArray($errors);
        $this->assertCount(3, $errors);
        $this->assertArrayHasKey('a', $errors);
        $this->assertArrayHasKey('b', $errors);
        $this->assertArrayHasKey('c', $errors);
    }

    public function testValidateRejectsTypeAsNonString(): void
    {
        $errors = WidgetSchema::validate([
            'window' => ['type' => 42],
        ]);
        $this->assertIsArray($errors);
        $this->assertArrayHasKey('window', $errors);
    }

    // -------- isToolbarEligible() --------

    public function testIsToolbarEligibleForCanonicalToolbarTypes(): void
    {
        foreach (WidgetSchema::TOOLBAR_ELIGIBLE_TYPES as $type) {
            $this->assertTrue(
                WidgetSchema::isToolbarEligible($type),
                "Expected '$type' to be toolbar-eligible"
            );
        }
    }

    public function testIsToolbarEligibleFalseForWidgetOnlyCanonicalTypes(): void
    {
        // From PRD §5.5 — these are canonical but widget-only (no
        // sensible board-level bulk-edit semantics).
        $this->assertFalse(WidgetSchema::isToolbarEligible('attribute_type_filter'));
        $this->assertFalse(WidgetSchema::isToolbarEligible('event_id_filter'));
    }

    public function testIsToolbarEligibleFalseForScalarTypes(): void
    {
        $this->assertFalse(WidgetSchema::isToolbarEligible('string'));
        $this->assertFalse(WidgetSchema::isToolbarEligible('int'));
        $this->assertFalse(WidgetSchema::isToolbarEligible('bool'));
        $this->assertFalse(WidgetSchema::isToolbarEligible('enum'));
    }

    public function testIsToolbarEligibleFalseForUnknownAndNonStringInputs(): void
    {
        $this->assertFalse(WidgetSchema::isToolbarEligible('made_up'));
        $this->assertFalse(WidgetSchema::isToolbarEligible(''));
        $this->assertFalse(WidgetSchema::isToolbarEligible(null));
        $this->assertFalse(WidgetSchema::isToolbarEligible(42));
        $this->assertFalse(WidgetSchema::isToolbarEligible(['time_window']));
    }
}
