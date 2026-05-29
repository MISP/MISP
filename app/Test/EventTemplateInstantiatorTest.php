<?php
/**
 * EventTemplateInstantiator unit tests — pre-DB paths only.
 *
 * The instantiator's execution order is:
 *   1. EventTemplateDependencies::requireAll()         (no DB)
 *   2. EventTemplateValidator::validate($definition)   (no DB unless the
 *      definition contains object_field elements — which we avoid here)
 *   3. validateUserInput($definition, $userInput)      (no DB)
 *   4. buildEventArray(...) + Event::_add(...)         (DB from here)
 *
 * These tests cover the three early-exit failure modes — invalid
 * definition, invalid user input (file_field rejection, unknown id,
 * missing mandatory) — that don't need a running DB. The DB-backed
 * success path (event creation, transactional rollback, post-hoc drop
 * detection) is covered by the Phase 1.6 integration tests against a
 * live MISP.
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
require_once __DIR__ . '/../Lib/Tools/EventTemplateInfoRenderer.php';
require_once __DIR__ . '/../Lib/Tools/EventTemplateInstantiationException.php';
require_once __DIR__ . '/../Lib/Tools/EventTemplateInstantiator.php';

use PHPUnit\Framework\TestCase;

class EventTemplateInstantiatorTest extends TestCase
{
    /** @var EventTemplateInstantiator */
    private $instantiator;

    /** @var array */
    private $user;

    protected function setUp(): void
    {
        $this->instantiator = new EventTemplateInstantiator();
        $this->user = array(
            'id' => 1,
            'org_id' => 1,
            'email' => 'analyst@example.org',
            'Role' => array('perm_add' => true),
        );
    }

    public function testInvalidDefinitionRaisesInstantiationException(): void
    {
        $def = $this->minimalValid();
        unset($def['schema_version']); // structurally invalid

        try {
            $this->instantiator->instantiate($def, array(), $this->user);
            $this->fail('expected EventTemplateInstantiationException');
        } catch (EventTemplateInstantiationException $e) {
            $this->assertStringContainsString(
                'Template definition is invalid',
                $e->getMessage()
            );
            $this->assertNotEmpty(
                $e->getErrors(),
                'expected a non-empty error list from the validator'
            );
        }
    }

    public function testFileFieldInputShapeIsValidated(): void
    {
        // With the Phase-2 upload pipeline in place, file_field inputs
        // must be {filename, data} objects (or arrays of them). A stray
        // scalar — e.g., someone submitting a plain filename string —
        // is rejected with a clear per-instance error.
        $def = $this->minimalValid();
        $def['structure'] = array(
            array(
                'type' => 'file_field',
                'id' => 'samples',
                'label' => 'Malware samples',
                'as' => 'attachment',
            ),
        );

        try {
            $this->instantiator->instantiate(
                $def,
                array('samples' => array(array('filename' => 'x.bin'))),
                $this->user
            );
            $this->fail('expected EventTemplateInstantiationException for missing data');
        } catch (EventTemplateInstantiationException $e) {
            $this->assertSame('User input is invalid.', $e->getMessage());
            $this->assertErrorContains(
                $e->getErrors(),
                'file_field "samples" instance 1: missing base64 data'
            );
        }
    }

    public function testFileFieldInputRejectsNonBase64Data(): void
    {
        $def = $this->minimalValid();
        $def['structure'] = array(
            array(
                'type' => 'file_field',
                'id' => 'samples',
                'label' => 'Samples',
                'as' => 'attachment',
            ),
        );

        try {
            $this->instantiator->instantiate(
                $def,
                array('samples' => array(
                    'filename' => 'x.bin',
                    'data' => '!!not-base64!!',
                )),
                $this->user
            );
            $this->fail('expected EventTemplateInstantiationException for bad base64');
        } catch (EventTemplateInstantiationException $e) {
            $this->assertErrorContains(
                $e->getErrors(),
                'data is not valid base64'
            );
        }
    }

    public function testUnknownUserInputIdIsRejected(): void
    {
        $def = $this->minimalValid();
        $def['structure'] = array(
            array(
                'type' => 'tag_field',
                'id' => 'tags_campaign',
                'label' => 'Campaign tags',
            ),
        );

        try {
            $this->instantiator->instantiate(
                $def,
                array('ghost' => 'whatever'),
                $this->user
            );
            $this->fail('expected EventTemplateInstantiationException');
        } catch (EventTemplateInstantiationException $e) {
            $this->assertSame('User input is invalid.', $e->getMessage());
            $this->assertErrorContains(
                $e->getErrors(),
                'unknown field id in user input: ghost'
            );
        }
    }

    public function testMissingMandatorySimpleFieldIsRejected(): void
    {
        $def = $this->minimalValid();
        $def['structure'] = array(
            array(
                'type' => 'tag_field',
                'id' => 'tags_campaign',
                'label' => 'Campaign tags',
                'mandatory' => true,
            ),
        );

        try {
            $this->instantiator->instantiate($def, array(), $this->user);
            $this->fail('expected EventTemplateInstantiationException');
        } catch (EventTemplateInstantiationException $e) {
            $this->assertSame('User input is invalid.', $e->getMessage());
            $this->assertErrorContains(
                $e->getErrors(),
                'mandatory field "tags_campaign" is empty'
            );
        }
    }

    public function testMandatoryFieldWithWhitespaceOnlyCountsAsEmpty(): void
    {
        $def = $this->minimalValid();
        $def['structure'] = array(
            array(
                'type' => 'tag_field',
                'id' => 'tags_campaign',
                'label' => 'Campaign tags',
                'mandatory' => true,
            ),
        );

        try {
            $this->instantiator->instantiate(
                $def,
                array('tags_campaign' => '   '),
                $this->user
            );
            $this->fail('expected EventTemplateInstantiationException');
        } catch (EventTemplateInstantiationException $e) {
            $this->assertErrorContains(
                $e->getErrors(),
                'mandatory field "tags_campaign" is empty'
            );
        }
    }

    public function testExceptionCarriesMultipleErrorsAtOnce(): void
    {
        // Two independent failures in one call — one file_field rejection,
        // one unknown-id rejection — should both surface on the same
        // exception instance (no early-return between the checks).
        $def = $this->minimalValid();
        $def['structure'] = array(
            array(
                'type' => 'file_field',
                'id' => 'samples',
                'label' => 'Samples',
            ),
            array(
                'type' => 'tag_field',
                'id' => 'tags_campaign',
                'label' => 'Tags',
            ),
        );

        try {
            $this->instantiator->instantiate(
                $def,
                array(
                    // Invalid file_field: missing `data` key.
                    'samples' => array(array('filename' => 'x.bin')),
                    // Unknown id.
                    'ghost' => 'whatever',
                ),
                $this->user
            );
            $this->fail('expected EventTemplateInstantiationException');
        } catch (EventTemplateInstantiationException $e) {
            $errors = $e->getErrors();
            $this->assertErrorContains($errors, 'file_field "samples"');
            $this->assertErrorContains($errors, 'unknown field id in user input: ghost');
        }
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

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

    private function assertErrorContains(array $errors, string $needle): void
    {
        $hits = array_filter(
            $errors,
            static function ($e) use ($needle) {
                return is_string($e) && stripos($e, $needle) !== false;
            }
        );
        $this->assertNotEmpty(
            $hits,
            sprintf(
                "expected an error containing '%s', got: %s",
                $needle,
                json_encode($errors)
            )
        );
    }
}
