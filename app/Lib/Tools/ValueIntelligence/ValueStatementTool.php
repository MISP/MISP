<?php

/**
 * What a reporter said about its own claim, read off the taxonomy tags
 * it put on the value's occurrences or on the event.
 *
 * Two families. **Confidence** — `admiralty-scale`'s information
 * credibility and `estimative-language`'s likelihood and analytic
 * confidence — is how sure the reporter is, scored on the signal strength
 * axis by `record.stated_confidence`. **False-positive warnings** —
 * the `false-positive` taxonomy's `risk` and `confirmed` — say the
 * value may be harmless, and are a benign voice in the lean.
 *
 * The context's `statements` block carries the raw tags, per event and
 * per level; this resolves them. **The occurrence level wins, per
 * family**: an event whose occurrences of the value state a
 * confidence is read there, and the event's own tags only where they
 * say nothing — an event about a campaign is not a statement about
 * every value in it if the reporter said something closer.
 *
 * Pure and static: it reads the context and issues nothing.
 */
class ValueStatementTool
{
    /** The confidence predicates, as `namespace:predicate`. */
    const CONFIDENCE = array(
        'admiralty-scale:information-credibility',
        'estimative-language:likelihood-probability',
        'estimative-language:confidence-in-analytic-judgment',
    );

    /**
     * The warnings, `namespace:predicate="value"` => the share of the
     * reporter's voice it turns benign. A risk the reporter rates low
     * or cannot judge, and an explicit *not* a false positive, are no
     * voice.
     */
    const WARNINGS = array(
        'false-positive:risk="high"' => 1.0,
        'false-positive:risk="medium"' => 0.5,
        'false-positive:confirmed="true"' => 1.0,
    );

    /** The predicates the context builder resolves tag ids for. */
    public static function predicates()
    {
        return array_merge(self::CONFIDENCE, array(
            'false-positive:risk',
            'false-positive:confirmed',
        ));
    }

    /**
     * A machine tag pulled apart, with its value quoted the way
     * `WARNINGS` keys it.
     *
     * @param string $name
     * @return array|null `predicate` (`ns:pred`) and `tag` (canonical)
     */
    public static function parse($name)
    {
        if (!preg_match('/^([^:="]+):([^=]+)="?([^"]*)"?$/',
            (string)$name, $parts)
        ) {
            return null;
        }
        $predicate = $parts[1] . ':' . $parts[2];
        return array(
            'predicate' => $predicate,
            'tag' => $predicate . '="' . $parts[3] . '"',
            'value' => $parts[3],
        );
    }

    /**
     * Each reporting organisation's stated confidence, in `[−1, 1]`.
     *
     * A reading is `(n − 50) / 50` from the taxonomy's own number, so
     * the midpoint of every scale — admiralty's *truth cannot be
     * judged* included — states nothing either way. Readings average
     * within an event's level, and an organisation's events average.
     *
     * @param array $context
     * @return array org id => `reading`, `events`, `tags` (names read)
     */
    public static function confidenceByOrg(array $context)
    {
        $out = array();
        foreach (self::events($context) as $event) {
            $readings = array();
            $names = array();
            foreach (self::level($event, 'confidence') as $tag) {
                if ($tag['number'] === null) {
                    continue;
                }
                $readings[] = max(-1.0, min(1.0,
                    ((float)$tag['number'] - 50.0) / 50.0));
                $names[] = $tag['name'];
            }
            if (empty($readings)) {
                continue;
            }
            $org = (int)$event['org'];
            $out[$org]['sum'] = ($out[$org]['sum'] ?? 0.0)
                + array_sum($readings) / count($readings);
            $out[$org]['events'] = ($out[$org]['events'] ?? 0) + 1;
            $out[$org]['tags'] = array_values(array_unique(array_merge(
                $out[$org]['tags'] ?? array(), $names)));
        }
        foreach ($out as $org => $entry) {
            $out[$org] = array(
                'reading' => $entry['sum'] / $entry['events'],
                'events' => $entry['events'],
                'tags' => $entry['tags'],
            );
        }
        return $out;
    }

    /**
     * Each reporting organisation's false-positive warning, from its
     * newest event that states one.
     *
     * An event stating both a risk and a confirmation reads the
     * heavier, since both are the same reporter on the same report.
     *
     * @param array $context
     * @return array org id => `weight`, `tag`, `at`
     */
    public static function warningsByOrg(array $context)
    {
        $out = array();
        foreach (self::events($context) as $event) {
            $tags = self::level($event, 'warning');
            if (empty($tags)) {
                continue;
            }
            $weight = 0.0;
            $tag = $tags[0]['tag'];
            foreach ($tags as $candidate) {
                $w = self::WARNINGS[$candidate['tag']] ?? 0.0;
                if ($w > $weight) {
                    $weight = $w;
                    $tag = $candidate['tag'];
                }
            }
            $org = (int)$event['org'];
            $at = (int)($event['last'] ?? 0);
            if (!isset($out[$org]) || $at > $out[$org]['at']) {
                $out[$org] = array('weight' => $weight, 'tag' => $tag,
                    'at' => $at);
            }
        }
        return $out;
    }

    /**
     * How a warning tag reads in a sentence.
     *
     * @param string $tag
     * @return string
     */
    public static function warningLabel($tag)
    {
        $labels = array(
            'false-positive:risk="high"' => __('a high false-positive'
                . ' risk'),
            'false-positive:risk="medium"' => __('a medium'
                . ' false-positive risk'),
            'false-positive:risk="low"' => __('a low false-positive'
                . ' risk'),
            'false-positive:risk="cannot-be-judged"' => __('a'
                . ' false-positive risk it cannot judge'),
            'false-positive:confirmed="true"' => __('a confirmed false'
                . ' positive'),
            'false-positive:confirmed="false"' => __('not a false'
                . ' positive'),
        );
        return $labels[$tag] ?? $tag;
    }

    /**
     * A reporting organisation's name off the context's `orgs`.
     *
     * @param array $context
     * @param int $orgId
     * @return string
     */
    public static function orgName(array $context, $orgId)
    {
        foreach ($context['orgs'] ?? array() as $org) {
            if ((int)($org['id'] ?? 0) === (int)$orgId
                && ($org['name'] ?? '') !== ''
            ) {
                return $org['name'];
            }
        }
        return __('A reporter');
    }

    /**
     * @param array $context
     * @return array
     */
    private static function events(array $context)
    {
        return isset($context['statements']['events'])
            && is_array($context['statements']['events'])
            ? $context['statements']['events']
            : array();
    }

    /**
     * One family's tags on one event, from the occurrence level when it
     * states anything in that family and from the event otherwise.
     *
     * @param array $event
     * @param string $family `confidence` or `warning`
     * @return array Each `name`, `tag`, `number`
     */
    private static function level(array $event, $family)
    {
        foreach (array('attribute', 'event') as $level) {
            $found = array();
            foreach ($event[$level] ?? array() as $tag) {
                $parsed = self::parse($tag['name'] ?? '');
                if ($parsed === null) {
                    continue;
                }
                $inFamily = $family === 'confidence'
                    ? in_array($parsed['predicate'], self::CONFIDENCE,
                        true)
                    : strpos($parsed['predicate'], 'false-positive:')
                        === 0;
                if (!$inFamily) {
                    continue;
                }
                $found[] = array(
                    'name' => $tag['name'],
                    'tag' => $parsed['tag'],
                    'number' => isset($tag['number'])
                        && is_numeric($tag['number'])
                        ? (int)$tag['number']
                        : null,
                );
            }
            if (!empty($found)) {
                return $found;
            }
        }
        return array();
    }
}
