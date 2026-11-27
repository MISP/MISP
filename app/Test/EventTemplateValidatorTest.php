<?php
/**
 * EventTemplateValidator unit tests.
 *
 * Follows the pure-PHPUnit convention used by every other test under
 * app/Test/: no CakePHP bootstrap, no DB. The validator's semantic layer
 * has two DB-backed paths (attribute_field category+type validity via
 * MispAttribute, and object_field object-template installation via
 * ObjectTemplate) that this suite deliberately avoids — those are
 * covered by the integration tests in /tests/. Everything else the
 * validator does — structural (JSON-schema) validation, duplicate-id
 * detection, object_reference endpoint wiring, and info_template
 * `{{field:<id>}}` reference resolution — is DB-independent and fully
 * covered here.
 *
 * Stubs `App::uses()` and the CakePHP `APP` / `DS` constants with just
 * enough shape for the validator's `App::uses(...)` / `loadSchema()`
 * calls. ClassRegistry is not stubbed; tests are written to stay off
 * the code paths that would invoke it.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package = null)
        {
        }
    }
}
if (!defined('APP')) {
    define('APP', dirname(__DIR__) . DIRECTORY_SEPARATOR);
}
if (!defined('DS')) {
    define('DS', DIRECTORY_SEPARATOR);
}
if (!function_exists('__')) {
    function __($s)
    {
        $args = func_get_args();
        return count($args) > 1 ? vsprintf($s, array_slice($args, 1)) : $s;
    }
}

require_once __DIR__ . '/../Lib/Tools/EventTemplateDependencyMissingException.php';
require_once __DIR__ . '/../Lib/Tools/EventTemplateDependencies.php';
require_once __DIR__ . '/../Lib/Tools/EventTemplateValidator.php';

use PHPUnit\Framework\TestCase;

class EventTemplateValidatorTest extends TestCase
{
    /** @var EventTemplateValidator */
    private $validator;

    protected function setUp(): void
    {
        $this->validator = new EventTemplateValidator();
    }

    // -----------------------------------------------------------------
    // Structural (JSON-schema) layer
    // -----------------------------------------------------------------

    public function testMinimalValidDefinitionHasNoErrors(): void
    {
        $this->assertSame(array(), $this->validator->validate($this->minimalValid()));
    }

    public function testStructureMayBeEmpty(): void
    {
        $def = $this->minimalValid();
        $def['structure'] = array();
        $this->assertSame(array(), $this->validator->validate($def));
    }

    public function testMissingSchemaVersionIsRejected(): void
    {
        $def = $this->minimalValid();
        unset($def['schema_version']);
        $this->assertSchemaErrorContains('schema_version', $this->validator->validate($def));
    }

    public function testWrongSchemaVersionIsRejected(): void
    {
        $def = $this->minimalValid();
        $def['schema_version'] = 2;
        $errors = $this->validator->validate($def);
        $this->assertNotEmpty($errors, 'expected schema_version=2 to be rejected');
    }

    public function testMissingUuidIsRejected(): void
    {
        $def = $this->minimalValid();
        unset($def['uuid']);
        $this->assertSchemaErrorContains('uuid', $this->validator->validate($def));
    }

    public function testMalformedUuidIsRejected(): void
    {
        // json-schema has no "uuid" format; the schema's pattern carries it
        $def = $this->minimalValid();
        $def['uuid'] = 'not-a-uuid';
        $this->assertSchemaErrorContains('uuid', $this->validator->validate($def));
    }

    public function testMissingNameIsRejected(): void
    {
        $def = $this->minimalValid();
        unset($def['name']);
        $this->assertSchemaErrorContains('name', $this->validator->validate($def));
    }

    public function testEmptyNameIsRejected(): void
    {
        $def = $this->minimalValid();
        $def['name'] = '';
        $errors = $this->validator->validate($def);
        $this->assertNotEmpty($errors, 'empty name should fail minLength=1');
    }

    public function testMissingEventDefaultsIsRejected(): void
    {
        $def = $this->minimalValid();
        unset($def['event_defaults']);
        $this->assertSchemaErrorContains('event_defaults', $this->validator->validate($def));
    }

    public function testUnknownElementTypeIsRejected(): void
    {
        $def = $this->minimalValid();
        $def['structure'] = array(array(
            'type' => 'not_a_real_type',
            'id' => 'x',
            'label' => 'x',
        ));
        $errors = $this->validator->validate($def);
        $this->assertNotEmpty($errors, 'unknown element type should fail oneOf');
    }

    public function testSectionRequiresLabel(): void
    {
        $def = $this->minimalValid();
        $def['structure'] = array(array(
            'type' => 'section',
            'id' => 's1',
            'label' => '',
        ));
        $errors = $this->validator->validate($def);
        $this->assertNotEmpty($errors, 'empty label on section should fail minLength=1');
    }

    public function testIdentifierPatternIsEnforced(): void
    {
        $def = $this->minimalValid();
        $def['structure'] = array(array(
            'type' => 'section',
            'id' => '1-not-valid',
            'label' => 's',
        ));
        $errors = $this->validator->validate($def);
        $this->assertNotEmpty($errors, 'element id violating identifier pattern should fail');
    }

    public function testAttributeFieldRequiresMispBlock(): void
    {
        $def = $this->minimalValid();
        $def['structure'] = array(array(
            'type' => 'attribute_field',
            'id' => 'sender',
            'label' => 'Sender',
        ));
        $errors = $this->validator->validate($def);
        $this->assertNotEmpty($errors, 'attribute_field must have misp.category + misp.type');
    }

    public function testAttributeFieldEmptyLabelIsRejected(): void
    {
        $def = $this->minimalValid();
        $def['structure'] = array(array(
            'type' => 'attribute_field',
            'id' => 'sender',
            'label' => '',
            // No 'misp' block — intentional: keeps the semantic layer's
            // category+type check off the DB-backed MispAttribute path.
        ));
        $errors = $this->validator->validate($def);
        $this->assertNotEmpty($errors, 'empty label on attribute_field must fail');
    }

    public function testDistributionOutOfRangeIsRejected(): void
    {
        $def = $this->minimalValid();
        $def['event_defaults'] = array('distribution' => 99);
        $errors = $this->validator->validate($def);
        $this->assertNotEmpty($errors, 'distribution=99 must fail enum');
    }

    public function testSharingGroupIdRequiredWhenDistributionIs4(): void
    {
        $def = $this->minimalValid();
        $def['event_defaults'] = array('distribution' => 4);
        $this->assertSchemaErrorContains('sharing_group_id', $this->validator->validate($def));

        $def['event_defaults']['sharing_group_id'] = 5;
        $this->assertEmpty($this->grepErrors($this->validator->validate($def), 'sharing_group_id'));
    }

    public function testInfoTemplateMalformedVariableIsRejected(): void
    {
        $def = $this->minimalValid();
        $def['event_defaults'] = array(
            'info_template' => 'Bad {{nonsense}} template',
        );
        $errors = $this->validator->validate($def);
        $this->assertNotEmpty($errors, 'unknown info_template variable must fail pattern');
    }

    public function testInfoTemplateWithValidVariablesIsAccepted(): void
    {
        $def = $this->minimalValid();
        $def['event_defaults'] = array(
            'info_template' => 'X {{date}} {{now}} {{user}} ok',
        );
        $this->assertSame(array(), $this->validator->validate($def));
    }

    // -----------------------------------------------------------------
    // Semantic layer (DB-independent paths)
    // -----------------------------------------------------------------

    public function testDuplicateElementIdsAreFlagged(): void
    {
        $def = $this->minimalValid();
        $def['structure'] = array(
            array('type' => 'section', 'id' => 'dup', 'label' => 'one'),
            array('type' => 'section', 'id' => 'dup', 'label' => 'two'),
        );
        $errors = $this->validator->validate($def);
        $this->assertNotEmpty($this->grepErrors($errors, 'duplicate element id'));
    }

    public function testObjectReferenceFromPointingAtUnknownIdIsFlagged(): void
    {
        $def = $this->minimalValid();
        $def['structure'] = array(
            array(
                'type' => 'object_reference',
                'id' => 'ref1',
                'from' => 'does_not_exist',
                'to' => 'also_does_not_exist',
                'relationship_type' => 'has-attachment',
            ),
        );
        $errors = $this->validator->validate($def);
        $this->assertNotEmpty(
            $this->grepErrors($errors, 'object_reference from "does_not_exist"')
        );
        $this->assertNotEmpty(
            $this->grepErrors($errors, 'object_reference to "also_does_not_exist"')
        );
    }

    public function testObjectReferenceToNonObjectFieldIsFlagged(): void
    {
        // Points at a section id — that element exists but isn't an
        // object_field, so the reference is invalid.
        $def = $this->minimalValid();
        $def['structure'] = array(
            array('type' => 'section', 'id' => 'sec1', 'label' => 's'),
            array(
                'type' => 'object_reference',
                'id' => 'ref1',
                'from' => 'sec1',
                'to' => 'sec1',
                'relationship_type' => 'has-attachment',
            ),
        );
        $errors = $this->validator->validate($def);
        $this->assertNotEmpty(
            $this->grepErrors($errors, 'object_reference from "sec1"')
        );
    }

    public function testInfoTemplateFieldRefResolvesToElementId(): void
    {
        $def = $this->minimalValid();
        $def['event_defaults'] = array(
            'info_template' => 'Spear {{field:sec1}}',
        );
        $def['structure'] = array(
            array('type' => 'section', 'id' => 'sec1', 'label' => 's'),
        );
        $this->assertSame(array(), $this->validator->validate($def));
    }

    public function testInfoTemplateFieldRefToUnknownIdIsFlagged(): void
    {
        $def = $this->minimalValid();
        $def['event_defaults'] = array(
            'info_template' => 'Spear {{field:ghost}}',
        );
        $errors = $this->validator->validate($def);
        $this->assertNotEmpty(
            $this->grepErrors($errors, 'info_template references unknown field id: ghost')
        );
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /**
     * Minimal structurally-valid definition. Keeps the structure empty
     * and event_defaults empty so the happy path stays off every
     * DB-backed semantic code path.
     */
    private function minimalValid(): array
    {
        return array(
            'schema_version' => 1,
            'uuid' => 'b3c9a7c2-1f2a-4f5b-9b4e-a1e5b0c9e6a2',
            'name' => 'Minimal',
            'event_defaults' => array('distribution' => 0),
            'structure' => array(),
        );
    }

    private function assertSchemaErrorContains(string $needle, array $errors): void
    {
        $this->assertNotEmpty(
            $this->grepErrors($errors, $needle),
            sprintf(
                "expected an error containing '%s', got: %s",
                $needle,
                json_encode($errors)
            )
        );
    }

    private function grepErrors(array $errors, string $needle): array
    {
        return array_values(array_filter(
            $errors,
            static function ($e) use ($needle) {
                return is_string($e) && stripos($e, $needle) !== false;
            }
        ));
    }
}
