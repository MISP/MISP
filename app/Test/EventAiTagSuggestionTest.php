<?php
/**
 * Event::classifyAiTagSuggestions() and aiTagResultMessage() (AI UX P5.1):
 * the AI module's tag suggestions are classified against what the instance
 * holds — tag rows, galaxy clusters, the tags already on the event, the
 * user's tag editor permission, the local flag and taxonomy exclusivity —
 * into one row per name with a status, and the counts of an accept are
 * summed up in one sentence. Both are pure static helpers.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB (the app/Test convention).
 * Event.php needs App::uses(), AppModel and the APP constant at load time;
 * Tag.php provides the galaxy-name regex.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!defined('APP')) {
    define('APP', __DIR__ . '/../');
}
if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }

        public static function import($type = null, $name = null, $parent = true)
        {
        }
    }
}
if (!class_exists('AppModel', false)) {
    class AppModel
    {
    }
}
if (!function_exists('__')) {
    function __($text, ...$args)
    {
        return $args ? vsprintf($text, $args) : $text;
    }
}
if (!function_exists('__n')) {
    function __n($singular, $plural, $count, ...$args)
    {
        return vsprintf($count == 1 ? $singular : $plural, $args ?: [$count]);
    }
}

require_once __DIR__ . '/../Model/Tag.php';
require_once __DIR__ . '/../Model/Event.php';

class EventAiTagSuggestionTest extends TestCase
{
    const APT1 = 'misp-galaxy:threat-actor="APT1"';

    /** Tag rows keyed by lower-cased name, as aiClassifyTagNames() builds them. */
    private static function tags(array $overrides = [])
    {
        $tags = [
            'tlp:amber' => ['id' => 1, 'name' => 'tlp:amber', 'colour' => '#FFC000', 'is_galaxy' => 0, 'local_only' => 0, 'usable' => true],
            'tlp:red' => ['id' => 2, 'name' => 'tlp:red', 'colour' => '#CC0033', 'is_galaxy' => 0, 'local_only' => 0, 'usable' => true],
            'org-only:secret' => ['id' => 3, 'name' => 'org-only:secret', 'colour' => '#000000', 'is_galaxy' => 0, 'local_only' => 0, 'usable' => false],
            'local:thing' => ['id' => 4, 'name' => 'local:thing', 'colour' => '#123456', 'is_galaxy' => 0, 'local_only' => 1, 'usable' => true],
        ];
        return array_merge($tags, $overrides);
    }

    private static function clusters()
    {
        return [
            mb_strtolower(self::APT1) => ['id' => 42, 'local_only' => false],
            'misp-galaxy:private="x"' => ['id' => 43, 'local_only' => true],
        ];
    }

    private static function byName(array $rows)
    {
        $out = [];
        foreach ($rows as $row) {
            $out[$row['name']] = $row;
        }
        return $out;
    }

    // --- shape ------------------------------------------------------------

    public function testRowsKeepTheModuleOrderAndDropBlanksAndDuplicates()
    {
        $rows = Event::classifyAiTagSuggestions(
            ['tlp:amber', '', '  ', 'TLP:AMBER', 'new:tag', 42, 'new:tag '],
            self::tags(), [], [], true, false
        );
        $this->assertSame(['tlp:amber', 'new:tag'], array_column($rows, 'name'));
    }

    public function testAnExistingTagCarriesItsStoredSpellingColourAndId()
    {
        $rows = Event::classifyAiTagSuggestions(['TLP:Amber'], self::tags(), [], [], true, false);
        $this->assertSame('tlp:amber', $rows[0]['name']);
        $this->assertSame('#FFC000', $rows[0]['colour']);
        $this->assertSame(1, $rows[0]['tag_id']);
        $this->assertTrue($rows[0]['exists']);
        $this->assertSame(Event::AI_TAG_OK, $rows[0]['status']);
        $this->assertTrue($rows[0]['selectable']);
        $this->assertSame('', $rows[0]['reason']);
    }

    public function testAnUnknownTagHasNoColourOrIdYet()
    {
        $rows = Event::classifyAiTagSuggestions(['brand:new'], self::tags(), [], [], true, false);
        $this->assertFalse($rows[0]['exists']);
        $this->assertNull($rows[0]['colour']);
        $this->assertNull($rows[0]['tag_id']);
        $this->assertNull($rows[0]['cluster_id']);
        $this->assertFalse($rows[0]['is_galaxy']);
        $this->assertSame(Event::AI_TAG_OK, $rows[0]['status']);
    }

    // --- statuses ---------------------------------------------------------

    public function testATagAlreadyOnTheEventIsPresentWhateverItsCase()
    {
        $rows = self::byName(Event::classifyAiTagSuggestions(
            ['tlp:amber', 'brand:new'], self::tags(), [], ['TLP:AMBER', 'Brand:New'], true, false
        ));
        $this->assertSame(Event::AI_TAG_PRESENT, $rows['tlp:amber']['status']);
        $this->assertSame(Event::AI_TAG_PRESENT, $rows['brand:new']['status']);
        $this->assertFalse($rows['tlp:amber']['selectable']);
        $this->assertNotSame('', $rows['tlp:amber']['reason']);
    }

    public function testAnUnknownTagNeedsTheTagEditorPermission()
    {
        $rows = Event::classifyAiTagSuggestions(['brand:new'], self::tags(), [], [], false, false);
        $this->assertSame(Event::AI_TAG_NEEDS_TAG_EDITOR, $rows[0]['status']);
        $this->assertFalse($rows[0]['selectable']);
    }

    public function testATagReservedForAnotherOrgIsRestricted()
    {
        $rows = Event::classifyAiTagSuggestions(['org-only:secret'], self::tags(), [], [], true, false);
        $this->assertSame(Event::AI_TAG_RESTRICTED, $rows[0]['status']);
    }

    public function testALocalOnlyTagIsRefusedForAGlobalAttachButFineForALocalOne()
    {
        $global = Event::classifyAiTagSuggestions(['local:thing'], self::tags(), [], [], true, false);
        $local = Event::classifyAiTagSuggestions(['local:thing'], self::tags(), [], [], true, true);
        $this->assertSame(Event::AI_TAG_LOCAL_ONLY, $global[0]['status']);
        $this->assertSame(Event::AI_TAG_OK, $local[0]['status']);
    }

    public function testAGalaxyNameWithAClusterIsAttachableThroughTheClusterWithoutATagRow()
    {
        $rows = Event::classifyAiTagSuggestions([self::APT1], self::tags(), self::clusters(), [], false, false);
        $this->assertSame(Event::AI_TAG_OK, $rows[0]['status'], 'no tag editor permission needed: the cluster makes the tag');
        $this->assertTrue($rows[0]['is_galaxy']);
        $this->assertSame(42, $rows[0]['cluster_id']);
        $this->assertFalse($rows[0]['exists']);
    }

    public function testAGalaxyNameWithATagRowKeepsItsClusterId()
    {
        $tags = self::tags([mb_strtolower(self::APT1) => ['id' => 9, 'name' => self::APT1, 'colour' => '#0088cc', 'is_galaxy' => 1, 'local_only' => 0, 'usable' => true]]);
        $rows = Event::classifyAiTagSuggestions([self::APT1], $tags, self::clusters(), [], false, false);
        $this->assertSame(Event::AI_TAG_OK, $rows[0]['status']);
        $this->assertSame(9, $rows[0]['tag_id']);
        $this->assertSame(42, $rows[0]['cluster_id']);
        $this->assertTrue($rows[0]['is_galaxy']);
    }

    public function testAGalaxyNameWithoutAClusterOrATagRowIsRefusedEvenForATagEditor()
    {
        $rows = Event::classifyAiTagSuggestions(['misp-galaxy:threat-actor="Nobody"'], self::tags(), self::clusters(), [], true, false);
        $this->assertSame(Event::AI_TAG_UNKNOWN_CLUSTER, $rows[0]['status']);
        $this->assertTrue($rows[0]['is_galaxy']);
    }

    public function testALocalOnlyGalaxyIsRefusedForAGlobalAttach()
    {
        $global = Event::classifyAiTagSuggestions(['misp-galaxy:private="x"'], [], self::clusters(), [], true, false);
        $local = Event::classifyAiTagSuggestions(['misp-galaxy:private="x"'], [], self::clusters(), [], true, true);
        $this->assertSame(Event::AI_TAG_LOCAL_ONLY, $global[0]['status']);
        $this->assertSame(Event::AI_TAG_OK, $local[0]['status']);
    }

    public function testTheExclusivityCheckSeesTheStoredNameAndTheEventTags()
    {
        $calls = [];
        $exclusive = function ($name, array $eventTagNames) use (&$calls) {
            $calls[] = [$name, $eventTagNames];
            return $name !== 'tlp:red';
        };
        $rows = self::byName(Event::classifyAiTagSuggestions(
            ['TLP:RED', 'brand:new'], self::tags(), [], ['tlp:amber'], true, false, $exclusive
        ));
        $this->assertSame(Event::AI_TAG_EXCLUSIVE, $rows['tlp:red']['status']);
        $this->assertSame(Event::AI_TAG_OK, $rows['brand:new']['status']);
        $this->assertSame([['tlp:red', ['tlp:amber']], ['brand:new', ['tlp:amber']]], $calls);
    }

    public function testTheExclusivityCheckIsNotAskedAboutRowsAlreadyRefused()
    {
        $asked = 0;
        $exclusive = function () use (&$asked) {
            $asked++;
            return false;
        };
        $rows = self::byName(Event::classifyAiTagSuggestions(
            ['tlp:amber', 'org-only:secret', 'brand:new'], self::tags(), [], ['tlp:amber'], false, false, $exclusive
        ));
        $this->assertSame(0, $asked);
        $this->assertSame(Event::AI_TAG_PRESENT, $rows['tlp:amber']['status']);
        $this->assertSame(Event::AI_TAG_RESTRICTED, $rows['org-only:secret']['status']);
        $this->assertSame(Event::AI_TAG_NEEDS_TAG_EDITOR, $rows['brand:new']['status']);
    }

    public function testEveryStatusHasAReasonExceptOk()
    {
        foreach ([Event::AI_TAG_PRESENT, Event::AI_TAG_NEEDS_TAG_EDITOR, Event::AI_TAG_UNKNOWN_CLUSTER, Event::AI_TAG_RESTRICTED, Event::AI_TAG_LOCAL_ONLY, Event::AI_TAG_EXCLUSIVE] as $status) {
            $this->assertNotSame('', Event::aiTagStatusText($status), $status);
        }
        $this->assertSame('', Event::aiTagStatusText(Event::AI_TAG_OK));
    }

    // --- result message ---------------------------------------------------

    public function testTheMessageCountsAttachedCreatedSkippedAndFailed()
    {
        $message = Event::aiTagResultMessage(['attached' => 3, 'created' => 1, 'skipped' => 2, 'failed' => 1, 'local' => false]);
        $this->assertSame('3 tags attached (1 created), 2 skipped (already present), 1 failed.', $message);
    }

    public function testTheMessageOmitsZeroCountsAndUsesTheSingular()
    {
        $this->assertSame('1 tag attached.', Event::aiTagResultMessage(['attached' => 1]));
        $this->assertSame('0 tags attached, 1 skipped (already present).', Event::aiTagResultMessage(['attached' => 0, 'skipped' => 1]));
    }

    public function testTheMessageSaysWhenTheTagsWentOnLocally()
    {
        $local = Event::aiTagResultMessage(['attached' => 2, 'local' => true]);
        $this->assertStringStartsWith('2 tags attached. ', $local);
        $this->assertStringContainsString('local', $local);
        $this->assertSame('0 tags attached, 1 failed.', Event::aiTagResultMessage(['attached' => 0, 'failed' => 1, 'local' => true]), 'nothing landed: no local note');
    }
}
