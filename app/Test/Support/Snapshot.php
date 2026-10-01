<?php

namespace MispTest\Support;

/**
 * Golden snapshots for PHP characterization tests.
 *
 * The PHP counterpart of tests/lib/snapshots.py, and it repeats that file's
 * hard-won rules rather than rediscovering them:
 *
 *  - Volatile values are ALIASED, not erased, so relationships survive: if two
 *    attributes share an event_id, the snapshot still shows that they do.
 *  - Identities are aliased PER TABLE, never by bare number. Auto-increment
 *    counters run independently per table, so on one database the first event
 *    and the first attribute both have id 1 and on another they do not. Keying
 *    the alias on the number alone lets that coincidence merge two unrelated
 *    tokens and renumber every later one - a snapshot recorded on a used
 *    instance then cannot match a clean CI database, for no reason a refactor
 *    caused. A foreign key is resolved to the table it points AT, so
 *    Attribute.event_id and Event.id still share one token.
 *  - Tokens are numbered PER KIND. A single counter across kinds couples id
 *    numbering to how many distinct timestamps appeared, so an unrelated
 *    run-to-run variation rewrites the whole file.
 *  - Timestamps and dates are erased, not numbered. Two rows written in the
 *    same second yield one distinct value, in the next second two - which
 *    would shift every later token. They carry no relational meaning anyway.
 *  - Tokens are assigned in document order, so the same structure always
 *    yields the same numbering.
 *
 * Regeneration is explicit (`UPDATE_SNAPSHOTS=1`) and never automatic: the
 * reviewable diff is the entire safety mechanism.
 */
class Snapshot
{
    /** Keys holding a database identity rather than content. */
    private const ID_KEYS = [
        'id', 'event_id', 'org_id', 'orgc_id', 'attribute_id', 'object_id',
        'sharing_group_id', 'user_id', 'role_id', 'sighting_id', 'tag_id',
        'galaxy_id', 'cluster_id', 'server_id', 'collection_id', 'uuid',
    ];

    /** Keys that are wall-clock and therefore never stable. */
    private const TIME_KEYS = [
        'timestamp', 'publish_timestamp', 'sighting_timestamp', 'date',
        'first_seen', 'last_seen', 'date_created', 'date_modified',
        'current_login', 'last_login',
    ];

    /**
     * The table a foreign key points at, so that Attribute.event_id and
     * Event.id alias to one token while Attribute.id keeps its own.
     */
    private const FOREIGN_KEY_TABLE = [
        'event_id' => 'Event',
        'org_id' => 'Org',
        'orgc_id' => 'Org',
        'attribute_id' => 'Attribute',
        'object_id' => 'Object',
        'sharing_group_id' => 'SharingGroup',
        'user_id' => 'User',
        'role_id' => 'Role',
        'sighting_id' => 'Sighting',
        'tag_id' => 'Tag',
        'galaxy_id' => 'Galaxy',
        'cluster_id' => 'GalaxyCluster',
        'server_id' => 'Server',
        'collection_id' => 'Collection',
    ];

    /**
     * CakePHP model keys that name the same table under two spellings.
     */
    private const TABLE_ALIASES = [
        'Orgc' => 'Org',
        'RelatedEvent' => 'Event',
    ];

    /** @var array<string,string> */
    private $seen = [];
    /** @var array<string,int> */
    private $counts = [];

    public static function of($value): string
    {
        $self = new self();
        return $self->render($self->walk($value, null, null));
    }

    private function token(string $kind, $value, string $scope = ''): string
    {
        if ($kind === 'time') {
            return '<time>';
        }
        $key = $kind . '|' . $scope . '|'
            . (is_scalar($value) ? (string)$value : gettype($value));
        if (!isset($this->seen[$key])) {
            $this->counts[$kind] = ($this->counts[$kind] ?? 0) + 1;
            $this->seen[$key] = sprintf('<%s:%d>', $kind, $this->counts[$kind]);
        }
        return $this->seen[$key];
    }

    /**
     * Which table an identity belongs to: the one a foreign key names, or
     * else the model key the value is nested under.
     */
    private function scopeOf(string $parentKey, ?string $table): string
    {
        if (isset(self::FOREIGN_KEY_TABLE[$parentKey])) {
            return self::FOREIGN_KEY_TABLE[$parentKey];
        }
        return $table ?? '';
    }

    private function walk($node, ?string $parentKey, ?string $table)
    {
        if (is_array($node)) {
            $isList = array_keys($node) === range(0, count($node) - 1);
            $out = [];
            if (!$isList) {
                ksort($node);
            }
            foreach ($node as $k => $v) {
                $childTable = $table;
                if (is_string($k) && $k !== '' && ctype_upper($k[0])) {
                    $childTable = self::TABLE_ALIASES[$k] ?? $k;
                }
                $out[$k] = $this->walk($v, is_string($k) ? $k : $parentKey, $childTable);
            }
            return $out;
        }
        if (is_object($node)) {
            return '<object:' . get_class($node) . '>';
        }
        if ($parentKey !== null && in_array($parentKey, self::TIME_KEYS, true)
            && $node !== null && $node !== '' && $node !== 0 && $node !== '0') {
            return $this->token('time', $node);
        }
        if ($parentKey !== null && in_array($parentKey, self::ID_KEYS, true)
            && $node !== null && $node !== '' && $node !== 0 && $node !== '0') {
            return $this->token('id', $node, $this->scopeOf($parentKey, $table));
        }
        return $node;
    }

    private function render($value): string
    {
        return json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    private static function path(string $name): string
    {
        return __DIR__ . DIRECTORY_SEPARATOR . 'snapshots' . DIRECTORY_SEPARATOR . $name . '.snapshot';
    }

    private static function updating(): bool
    {
        $flag = getenv('UPDATE_SNAPSHOTS');
        return $flag !== false && $flag !== '' && $flag !== '0' && $flag !== 'false';
    }

    /**
     * Compare against the committed snapshot.
     *
     * Returns [matched, message]. A missing snapshot fails: recording is only
     * ever done under UPDATE_SNAPSHOTS=1, so every golden file arrives through
     * a reviewable diff rather than through the run that checks it.
     */
    public static function compare(string $name, $actual, ?string $knownDefect = null): array
    {
        $body = self::of($actual);
        $header = '';
        if ($knownDefect !== null) {
            $header = "// KNOWN-DEFECT: {$knownDefect}\n"
                . "// Current behaviour, recorded so refactors are still detected.\n"
                . "// NOT the intended contract - see docs/adr/0002.\n";
        }
        $content = $header . $body;
        $path = self::path($name);

        // An uncommitted snapshot must FAIL, not record itself. Recording on
        // first sight looks convenient, but a golden file that is written by
        // the run it is meant to police compares nothing: the test passes on
        // CI, the file never reaches the repository, and it passes there
        // forever. Every snapshot has to be produced deliberately and land in
        // a reviewable diff, which is the entire safety mechanism.
        if (!self::updating() && !is_file($path)) {
            return [false, sprintf(
                "no committed snapshot %s.\nRe-run with UPDATE_SNAPSHOTS=1 to record it, then "
                . "commit the file so the contract it pins is reviewed. A snapshot recorded by "
                . "the run that checks it would assert nothing.",
                basename($path)
            )];
        }

        if (self::updating()) {
            $dir = dirname($path);
            if (!is_dir($dir) && !@mkdir($dir, 0777, true) && !is_dir($dir)) {
                throw new \RuntimeException("cannot create snapshot directory $dir");
            }
            // A silent write failure would make every snapshot assertion pass
            // without comparing anything - a suite that cannot fail. Fail loudly.
            if (@file_put_contents($path, $content) === false) {
                throw new \RuntimeException(
                    "cannot write snapshot $path - check that the directory is writable by the "
                    . "user running the tests. Silently skipping the write would make this "
                    . "entire suite vacuous."
                );
            }
            return [true, 'snapshot written: ' . basename($path)];
        }

        $expected = (string)file_get_contents($path);
        if ($expected === $content) {
            return [true, 'matches'];
        }
        return [false, self::diff($expected, $content, basename($path))];
    }

    private static function diff(string $expected, string $actual, string $name): string
    {
        $e = explode("\n", $expected);
        $a = explode("\n", $actual);
        $lines = [];
        foreach (array_slice($e, 0, max(count($e), count($a))) as $i => $line) {
            $other = $a[$i] ?? '<missing>';
            if ($line !== $other) {
                $lines[] = sprintf('  line %d:', $i + 1);
                $lines[] = '    committed: ' . $line;
                $lines[] = '    now:       ' . $other;
            }
            if (count($lines) > 45) {
                $lines[] = '  ... further differences truncated';
                break;
            }
        }
        return sprintf(
            "response contract changed in %s\n%s\n\nIf intended, re-run with UPDATE_SNAPSHOTS=1 "
            . "and commit the updated snapshot so the diff is reviewed.",
            $name,
            implode("\n", $lines)
        );
    }
}
