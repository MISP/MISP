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
 *
 * The galaxy tag-name resolver is covered here too, with the cluster
 * lookup stood in by EventTemplateInstantiatorWithFakeClusters below.
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
    // Galaxy tag-name resolution
    // -----------------------------------------------------------------

    public function testGalaxyValueResolvesToTheClustersOwnTagName(): void
    {
        $uuidTag = 'misp-galaxy:threat-actor="2ef58a58-0d68-4d1a-9b5f-2c0b6f30ee9c"';
        $i = $this->withClusters(array(
            'GalaxyCluster.value|apt28' => 'misp-galaxy:threat-actor="APT28"',
            'GalaxyCluster.value|custom actor' => $uuidTag,
        ));
        // Library cluster: named by value.
        $this->assertSame(
            'misp-galaxy:threat-actor="APT28"',
            $this->resolve($i, 'APT28', array('threat-actor'))
        );
        // Custom cluster: named by uuid, whatever the value says.
        $this->assertSame(
            $uuidTag,
            $this->resolve($i, 'Custom Actor', array('threat-actor'))
        );
        // Value lookups are restricted to the field's galaxy types.
        $this->assertSame(
            array('GalaxyCluster.value', 'APT28', array('threat-actor')),
            $i->lookups[0]
        );
    }

    public function testUuidAndTagNameInputsPinTheClusterWithoutTypeRestriction(): void
    {
        $uuid = '2ef58a58-0d68-4d1a-9b5f-2c0b6f30ee9c';
        $tag = 'misp-galaxy:threat-actor="' . $uuid . '"';
        $i = $this->withClusters(array(
            'GalaxyCluster.uuid|' . $uuid => $tag,
            'GalaxyCluster.tag_name|' . mb_strtolower($tag) => $tag,
        ));
        $this->assertSame($tag, $this->resolve($i, strtoupper($uuid), array('threat-actor')));
        $this->assertSame($tag, $this->resolve($i, $tag, array('threat-actor')));
        $this->assertCount(2, $i->lookups);
        $this->assertSame('GalaxyCluster.uuid', $i->lookups[0][0]);
        $this->assertSame('GalaxyCluster.tag_name', $i->lookups[1][0]);
        foreach ($i->lookups as $lookup) {
            $this->assertSame(array(), $lookup[2], 'uuid / tag-name lookups carry no type restriction');
        }
    }

    public function testCompleteTagNameIsNeverWrappedASecondTime(): void
    {
        // The Overmind picker submits the full tag name. Wrapping it again
        // used to yield misp-galaxy:threat-actor="misp-galaxy:threat-actor=…".
        $i = $this->withClusters(array());
        $tag = 'misp-galaxy:threat-actor="APT28"';
        $this->assertSame($tag, $this->resolve($i, $tag, array('threat-actor')));
    }

    public function testUnmatchedValueFallsBackToTheSynthesisedName(): void
    {
        $i = $this->withClusters(array());
        $this->assertSame(
            'misp-galaxy:threat-actor="Nobody"',
            $this->resolve($i, 'Nobody', array('threat-actor', 'tool'))
        );
        $this->assertSame(
            'misp-galaxy:unknown="Nobody"',
            $this->resolve($i, 'Nobody', array())
        );
    }

    public function testResolutionIsCachedPerInput(): void
    {
        $i = $this->withClusters(array(
            'GalaxyCluster.value|apt28' => 'misp-galaxy:threat-actor="APT28"',
        ));
        $this->resolve($i, 'APT28', array('threat-actor'));
        $this->resolve($i, ' APT28 ', array('threat-actor'));
        $this->assertCount(1, $i->lookups);
    }

    public function testEventTagNamesUseResolvedGalaxyTagNames(): void
    {
        $uuidTag = 'misp-galaxy:threat-actor="2ef58a58-0d68-4d1a-9b5f-2c0b6f30ee9c"';
        $i = $this->withClusters(array(
            'GalaxyCluster.value|apt28' => 'misp-galaxy:threat-actor="APT28"',
            'GalaxyCluster.value|custom actor' => $uuidTag,
        ));
        $def = $this->minimalValid();
        $def['event_defaults']['tags'] = array(array('name' => 'tlp:amber'));
        $def['event_defaults']['galaxy_clusters'] = array(
            array('galaxy_type' => 'threat-actor', 'value' => 'Custom Actor'),
        );
        $def['structure'] = array(
            array(
                'type' => 'galaxy_field',
                'id' => 'gal',
                'label' => 'Actor',
                'restrict_galaxy_types' => array('threat-actor'),
                'multiple' => true,
            ),
        );
        $m = new ReflectionMethod(EventTemplateInstantiator::class, 'collectEventTagNames');
        $m->setAccessible(true);
        $names = $m->invoke($i, $def, array('gal' => array('APT28', 'Custom Actor')), $this->user);
        // The default entry and the picked value name the same cluster,
        // so it is attached once, under the tag the cluster owns.
        $this->assertSame(
            array('tlp:amber', $uuidTag, 'misp-galaxy:threat-actor="APT28"'),
            $names
        );
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private function withClusters(array $clusters): EventTemplateInstantiatorWithFakeClusters
    {
        $i = new EventTemplateInstantiatorWithFakeClusters();
        $i->clusters = $clusters;
        return $i;
    }

    private function resolve(EventTemplateInstantiator $i, string $value, array $types): string
    {
        $m = new ReflectionMethod(EventTemplateInstantiator::class, 'resolveGalaxyTagName');
        $m->setAccessible(true);
        return $m->invoke($i, $value, $types, $this->user);
    }

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

/**
 * Stands in for the galaxy_clusters lookup so the resolver's
 * classification, fallback and caching run without a database.
 */
class EventTemplateInstantiatorWithFakeClusters extends EventTemplateInstantiator
{
    /** @var array<string,string> "<field>|<lowercased value>" -> tag_name */
    public $clusters = array();

    /** @var array list of [field, value, galaxyTypes] as received */
    public $lookups = array();

    protected function findGalaxyClusterTagName($field, $value, array $galaxyTypes, array $user)
    {
        $this->lookups[] = array($field, $value, $galaxyTypes);
        $key = $field . '|' . mb_strtolower($value);
        return isset($this->clusters[$key]) ? $this->clusters[$key] : null;
    }
}
