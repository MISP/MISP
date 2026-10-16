<?php

App::uses('ComplexTypeTool', 'Tools');

/**
 * What the reader typed, turned into values.
 *
 * `/values/index` has two ways in — a box that takes one value and a
 * box that takes a pasted list — and they must not disagree about what
 * a value is. One of them redirects to a profile and the other links to
 * a hundred of them; a reader who resolves `hxxp://evil[.]com` and gets
 * an answer, then pastes the same string in a list and gets nothing,
 * has been told the page is unreliable rather than that their input was
 * odd. So both go through this file.
 *
 * Three functions, and the difference between them is the whole
 * design:
 *
 *   normalise()      one string in, one value out. Splits nothing.
 *   normaliseMany()  a paste in, a list of values out. Splits.
 *   extractMany()    a paste in, the values *inside* it out.
 *
 * `normalise()` splitting nothing is what makes a value containing a
 * separator reachable at all — see the comma rule below.
 *
 * `extractMany()` is the reader's choice per paste and never a
 * default: it finds indicators in prose that the other two bury, and
 * it cannot type about half of what a MISP instance holds. It is here
 * rather than in the controller for the reason the other two are —
 * one parsing tool, so no two ways in can disagree about what a value
 * is (V4).
 *
 * **Nothing here is altered silently.** Both functions report every
 * transformation they applied, because the page renders the reader's
 * own strings back to them and a table whose rows are not the strings
 * the reader pasted is a table they cannot check. `normalise()` returns
 * a `changed` list; `normaliseMany()` returns counts under the same
 * token names, so the two cannot spell a transformation differently.
 *
 * **It does not lowercase.** The shipped schema collates `value1` as
 * `utf8mb3_unicode_ci` but an instance can run `utf8mb3_bin`, where
 * `Google.com` and `google.com` are different values — so case-folding
 * here would silently merge two values on one instance and not on the
 * other. Deduplication is exact for the same reason. Case is the
 * resolver's decision to make, once, on the miss path.
 *
 * Pure and static, and it takes no `$user`. It reads no table, so the
 * rules on querying `value1`/`value2` have nothing to say about it.
 */
class ValueInputTool
{
    /**
     * Wrapping quotes were stripped.
     *
     * The token is also the `report` key `normaliseMany()` counts
     * under, so the row's note and the summary line above the table
     * cannot name the same transformation two ways.
     */
    const UNQUOTED = 'unquoted';

    /** The same, for a value that arrived defanged. */
    const REFANGED = 'refanged';

    /**
     * How many values a paste may carry.
     *
     * About the size of a report's IOC section. It lives here rather
     * than on the controller because the page mirrors it client-side as
     * a live count, and two copies of a number the reader is measured
     * against drift.
     */
    const CAP = 100;

    /** One value per line; a comma is part of the value. */
    const BY_LINES = 'lines';

    /** One line; commas separate the values on it. */
    const BY_COMMAS = 'commas';

    /**
     * Every field the reader sent is a value. The page's default, and
     * the reading `normaliseMany()` makes.
     */
    const MODE_LINES = 'lines';

    /**
     * The paste is text, and the values are inside it. The reading
     * `extractMany()` makes, asked for by the reader per paste.
     */
    const MODE_EXTRACT = 'extract';

    /**
     * Quote pairs stripped when they wrap the whole value.
     *
     * The straight pair covers a CSV cell, the backtick a value lifted
     * out of markdown, and the typographic pairs a report pasted from a
     * PDF or a word processor — which is where an IOC section usually
     * comes from, and which is the reason the list is not just `"`.
     */
    const QUOTE_PAIRS = array(
        '"' => '"',
        "'" => "'",
        '`' => '`',
        '“' => '”',
        '‘' => '’',
    );

    /**
     * Trimmed from both ends on top of what `trim()` takes.
     *
     * A non-breaking space off a PDF, a zero-width space off a web
     * page, a byte-order mark on the first cell of an exported CSV —
     * all three are what an IOC section is pasted out of, and all three
     * produce a value that looks character-for-character like the one
     * the reader meant and matches nothing. That is the worst failure
     * this file can have, because the page then shows the reader their
     * own string beside an honest *not recorded*.
     */
    const TRIM_WIDE = array("\xC2\xA0", "\xE2\x80\x8B", "\xEF\xBB\xBF");

    /**
     * The defanged forms core's own table does not carry.
     *
     * Applied **before** `ComplexTypeTool::REFANG_REGEX_TABLE`, which
     * is not a detail: core's rule for `[.]` does not consume the
     * spaces around it, so `example [dot] com` would come out of it as
     * `example . com` — still three tokens, and no longer refangable by
     * anything. Running the bracket forms here first, spaces included,
     * is what makes the spaced variants work.
     *
     * The bare-word forms require a non-space on each side so that
     * ` dot ` and ` at ` only ever join two things that were already
     * adjacent to them. They are case-insensitive because analysts
     * write `DOT` as often as `dot`.
     */
    const REFANG_EXTRA = array(
        '/\s*[\[\(\{]\s*(?:\.|dot)\s*[\]\)\}]\s*/i' => '.',
        '/\s*[\[\(\{]\s*(?:@|at)\s*[\]\)\}]\s*/i' => '@',
        '/\s*[\[\(\{]\s*(?::|colon)\s*[\]\)\}]\s*/i' => ':',
        '/(?<=\S)\s+dot\s+(?=\S)/i' => '.',
        '/(?<=\S)\s+at\s+(?=\S)/i' => '@',
    );

    /**
     * One string, as a value.
     *
     * **Splits nothing.** Not on commas, not on `|`. A reader who means
     * one value means the string they typed, and this is the only path
     * on the page by which a value containing a separator can be
     * reached at all.
     *
     * Whitespace trimming is not reported. Every line of a paste made
     * on Windows carries a `\r`, so a `trimmed` token would appear on
     * every row of every such table and say nothing; the tokens that
     * are reported are the ones that change what the string *means*.
     *
     * @param string|null $raw
     * @return array{value: string|null, changed: array<string>}
     */
    public static function normalise($raw)
    {
        $changed = array();
        $value = self::trimValue((string)$raw);

        $unquoted = self::stripWrappingQuotes($value);
        if ($unquoted !== $value) {
            $changed[] = self::UNQUOTED;
            $value = self::trimValue($unquoted);
        }

        $refanged = self::refang($value);
        if ($refanged !== $value) {
            $changed[] = self::REFANGED;
            $value = self::trimValue($refanged);
        }

        return array(
            'value' => $value === '' ? null : $value,
            'changed' => $changed,
        );
    }

    /**
     * A paste, as a list of values.
     *
     * In order: choose the separator, normalise each field, split
     * composites, deduplicate preserving first-seen order, then cap.
     * The cap is applied last so that a reader who pasted the same
     * hundred values twice is not refused for it.
     *
     * **The separator is the paste's own.** A paste with more than one
     * line has already said what its unit is, and splitting those lines
     * on commas as well could only take values away from it; a paste on
     * one line has no other separator available, so commas govern
     * there. A pasted spreadsheet column and a pasted `a, b, c` list
     * therefore both work, and a value containing a comma survives when
     * it arrives among other lines — which is the documented limit of
     * comma-splitting rather than a solution to it. A value containing
     * a comma and pasted *alone* still splits; `normalise()` is where
     * that reader is served.
     *
     * `report` counts the input, not the returned slice: a value beyond
     * the cap still counted towards `refanged` and `duplicates`,
     * because the caller refuses an overflowing paste outright and the
     * numbers it refuses with should describe what was pasted.
     *
     * @param string|null $raw
     * @param int|null $cap Values returned at most; null or <1 for none
     * @return array{values: array<string>, report: array}
     */
    public static function normaliseMany($raw, $cap = self::CAP)
    {
        $raw = (string)$raw;
        /*
         * `/u` fails outright on a stray byte rather than skipping it,
         * and a paste out of a report carries one often enough that
         * losing the whole list to it is not acceptable. The byte-mode
         * split finds the same line breaks.
         */
        $lines = preg_split('/\R/u', $raw);
        if ($lines === false) {
            $lines = preg_split('/\R/', $raw);
        }
        $lines = self::cleanFields($lines === false ? array() : $lines);

        $separator = count($lines) > 1 ? self::BY_LINES : self::BY_COMMAS;
        if ($separator === self::BY_LINES) {
            $fields = $lines;
        } else {
            $only = isset($lines[0]) ? $lines[0] : '';
            $fields = self::cleanFields(explode(',', $only));
        }

        $report = array(
            'mode' => self::MODE_LINES,
            'lines' => count($lines),
            'fields' => count($fields),
            'separator' => $separator,
            'empty' => 0,
            'commas_kept' => 0,
            self::UNQUOTED => 0,
            self::REFANGED => 0,
            'composites' => 0,
            'duplicates' => 0,
            'wordy' => 0,
            'unread' => 0,
            'unread_example' => null,
            'total' => 0,
            'returned' => 0,
            'cap' => $cap,
            'overflow' => 0,
        );

        $produced = array();
        foreach ($fields as $field) {
            if ($separator === self::BY_LINES
                && strpos($field, ',') !== false
            ) {
                $report['commas_kept']++;
            }
            $one = self::normalise($field);
            if ($one['value'] === null) {
                $report['empty']++;
                continue;
            }
            $parts = self::splitComposite($one['value']);
            if (count($parts) > 1) {
                $report['composites']++;
            }
            foreach ($parts as $part) {
                $produced[] = array(
                    'value' => $part['value'],
                    'changed' => array_values(array_unique(
                        array_merge($one['changed'], $part['changed'])
                    )),
                );
            }
        }

        /*
         * `$seen` is keyed by the value, and PHP turns a key like
         * `'123'` into the integer 123 on the way in. That is harmless
         * for a membership test — two distinct strings never land on
         * one key — but it is why the values themselves are collected
         * in a separate list rather than read back off `array_keys()`,
         * which would hand the caller integers.
         */
        $seen = array();
        $values = array();
        foreach ($produced as $item) {
            if (isset($seen[$item['value']])) {
                $report['duplicates']++;
                continue;
            }
            $seen[$item['value']] = true;
            $values[] = $item['value'];
            foreach ($item['changed'] as $token) {
                $report[$token]++;
            }
        }

        $report['total'] = count($values);
        if ($cap !== null && $cap > 0 && count($values) > $cap) {
            $report['overflow'] = count($values) - $cap;
            $values = array_slice($values, 0, $cap);
        }
        $report['returned'] = count($values);
        $report['wordy'] = self::countWordy($values);

        return array('values' => $values, 'report' => $report);
    }

    /**
     * The same paste, read as text with the values inside it.
     *
     * `normaliseMany()` treats every field the reader sent as a value,
     * which is right for an IOC list and wrong for a report: a
     * paragraph becomes a row per sentence, each answering *not
     * recorded*. Worse than useless, in fact — `REFANG_EXTRA` turns
     * *URLs at the proxy* into `URLs@the proxy`, and a literal
     * `` `domain|ip` `` in the prose splits into two rows. This reads
     * the paste the other way: `ComplexTypeTool::checkFreeText()`, the
     * engine behind freetext import, finds the indicators and
     * everything around them is left alone.
     *
     * **It is the reader's choice per paste and never a default**
     * (`value-index.md` §11, V20). Measured against 2,114 values out
     * of a real instance, the extractor hands back 51.7% of them: 51
     * of 126 type-and-slot combinations lose every value — `AS`,
     * `cpe`, `user-agent`, `tlsh`, `yara`, `snort`, `mutex`, `port`,
     * `datetime`, every `target-*`, the whole person family. So this
     * function's job is not only to extract but to **count what it
     * could not read**, in `unread`, because a box that silently stops
     * answering for a `mutex` is the one failure this page's rules
     * forbid.
     *
     * **Still pure, and still takes no `$user`**
     * (`value-intelligence-live/00-contract.md` §14.5). `ComplexTypeTool`
     * accepts a TLD list and a security-vendor domain list, and
     * `EventsController::freeTextImport()` reads both off
     * `Warninglist`. Neither is passed here, because neither changes
     * *which strings survive* — only the `default_type` attached to
     * them, which this page never reads. Verified over the same 2,114
     * values: with a TLD list and without, the extracted set is
     * identical for every one of them.
     *
     * The composites are the one thing that must be undone. The
     * extractor returns `filename|md5` whole and even invents a
     * composite — `1.2.3.4:443` comes back as `1.2.3.4|443` — and no
     * column holds a pair (§1.1, V16), so every hit goes through the
     * same `splitComposite()` the line reading uses.
     *
     * @param string|null $raw
     * @param int|null $cap Values returned at most; null or <1 for none
     * @return array{values: array<string>, report: array}
     */
    public static function extractMany($raw, $cap = self::CAP)
    {
        $raw = (string)$raw;
        $lines = preg_split('/\R/u', $raw);
        if ($lines === false) {
            $lines = preg_split('/\R/', $raw);
        }
        $lines = self::cleanFields($lines === false ? array() : $lines);

        App::uses('ComplexTypeTool', 'Tools');
        $tool = new ComplexTypeTool();
        $hits = $tool->checkFreeText($raw);

        $report = array(
            'mode' => self::MODE_EXTRACT,
            'lines' => count($lines),
            'fields' => count($hits),
            'separator' => self::BY_LINES,
            'candidates' => count($hits),
            'empty' => 0,
            'commas_kept' => 0,
            self::UNQUOTED => 0,
            self::REFANGED => 0,
            'composites' => 0,
            'duplicates' => 0,
            'wordy' => 0,
            'unread' => 0,
            'unread_example' => null,
            'total' => 0,
            'returned' => 0,
            'cap' => $cap,
            'overflow' => 0,
        );

        $produced = array();
        foreach ($hits as $hit) {
            /*
             * `original_value` is the token as it stood in the text,
             * before the extractor refanged it — so *what was done to
             * get here* is read off the same comparison the line
             * reading makes, and the two cannot spell it differently.
             */
            $original = isset($hit['original_value'])
                ? (string)$hit['original_value']
                : (string)$hit['value'];
            $changed = self::refang($original) === $original
                ? array()
                : array(self::REFANGED);
            $parts = self::splitComposite((string)$hit['value']);
            if (count($parts) > 1) {
                $report['composites']++;
            }
            foreach ($parts as $part) {
                $produced[] = array(
                    'value' => $part['value'],
                    'changed' => array_values(array_unique(
                        array_merge($changed, $part['changed'])
                    )),
                );
            }
        }

        $seen = array();
        $values = array();
        foreach ($produced as $item) {
            if ($item['value'] === '') {
                continue;
            }
            if (isset($seen[$item['value']])) {
                $report['duplicates']++;
                continue;
            }
            $seen[$item['value']] = true;
            $values[] = $item['value'];
            foreach ($item['changed'] as $token) {
                $report[$token]++;
            }
        }

        $report['total'] = count($values);
        if ($cap !== null && $cap > 0 && count($values) > $cap) {
            $report['overflow'] = count($values) - $cap;
            $values = array_slice($values, 0, $cap);
        }
        $report['returned'] = count($values);
        $report['wordy'] = self::countWordy($values);

        $unread = self::unreadLines($lines, $values);
        $report['unread'] = count($unread);
        $report['unread_example'] = isset($unread[0]) ? $unread[0] : null;

        return array('values' => $values, 'report' => $report);
    }

    /**
     * Values that contain whitespace, which is the page's tell that a
     * paste was prose rather than a list.
     *
     * A `text` attribute legitimately holds a sentence, so this
     * proves nothing on its own — it is what the worklist uses to
     * decide whether to *offer* the other reading, never to take it.
     *
     * @param array<string> $values
     * @return int
     */
    private static function countWordy(array $values)
    {
        $wordy = 0;
        foreach ($values as $value) {
            if (preg_match('/\s/u', $value) || preg_match('/\s/', $value)) {
                $wordy++;
            }
        }
        return $wordy;
    }

    /**
     * Lines the reader plainly meant as values, that the extractor
     * gave nothing for.
     *
     * **This is the count the whole mode turns on.** The extractor
     * types about half of what a MISP instance holds and says nothing
     * about the rest; a reader who pastes a `mutex` among their hashes
     * would otherwise watch it vanish with no way to tell that from
     * *nobody recorded it*. So the page counts the lines it could not
     * read and offers them back.
     *
     * A line qualifies only if it looks like somebody meant it as one
     * value: no whitespace in it, at least one alphanumeric character,
     * and at least three characters long. That is what keeps a
     * markdown fence, a `---` rule and a `#` heading out of the count
     * — they are punctuation the reader never meant as a value, and a
     * caution that named them would be noise standing exactly where
     * the real warning has to be believed.
     *
     * A line *carries* a value when the value occurs inside it once
     * refanged, which is what makes `1.2.3.4:443` and
     * `invoice.doc|<md5>` count as read: both give their halves.
     *
     * @param array<string> $lines Cleaned lines of the paste
     * @param array<string> $values The values being returned
     * @return array<string> The unread lines, in the order pasted
     */
    private static function unreadLines(array $lines, array $values)
    {
        $unread = array();
        foreach ($lines as $line) {
            if (strlen($line) < 3) {
                continue;
            }
            if (preg_match('/\s/u', $line) || preg_match('/\s/', $line)) {
                continue;
            }
            if (!preg_match('/[a-z0-9]/i', $line)) {
                continue;
            }
            $refanged = self::refang($line);
            $carried = false;
            foreach ($values as $value) {
                if ($value !== '' && strpos($refanged, $value) !== false) {
                    $carried = true;
                    break;
                }
            }
            if (!$carried) {
                $unread[] = $line;
            }
        }
        return $unread;
    }

    /**
     * A composite's halves, each a value in its own right.
     *
     * `example.com|1.2.3.4` is one attribute and two identities: the
     * halves are what `value1` and `value2` hold, and `Value`'s own
     * docblock is explicit that a composite contributes two. Split on
     * the **first** pipe only, because every composite type MISP
     * defines has exactly two parts, so a later pipe belongs to the
     * second half.
     *
     * A value whose halves both normalise to nothing is handed back
     * whole rather than dropped — the reader gets their string and the
     * *not recorded* answer, which is better than a row that vanished.
     *
     * @param string $value A value, already normalised
     * @return array<array{value: string, changed: array<string>}>
     */
    private static function splitComposite($value)
    {
        if (strpos($value, '|') === false) {
            return array(array('value' => $value, 'changed' => array()));
        }
        $parts = array();
        foreach (explode('|', $value, 2) as $half) {
            $one = self::normalise($half);
            if ($one['value'] !== null) {
                $parts[] = $one;
            }
        }
        return $parts ? $parts
            : array(array('value' => $value, 'changed' => array()));
    }

    /**
     * A separator's units, trimmed, with the empty ones gone.
     *
     * @param array<string> $fields
     * @return array<string>
     */
    private static function cleanFields(array $fields)
    {
        $trimmed = array_map(
            function ($field) {
                return self::trimValue($field);
            },
            $fields
        );
        return array_values(array_filter($trimmed, 'strlen'));
    }

    /**
     * Whitespace off both ends, including the invisible kinds.
     *
     * Looped because the wide characters and the ASCII ones interleave
     * — a cell pasted out of a spreadsheet can arrive as BOM, space,
     * value — and one pass over each would leave the outer layer.
     *
     * @param string $value
     * @return string
     */
    private static function trimValue($value)
    {
        do {
            $before = $value;
            $value = trim($value);
            foreach (self::TRIM_WIDE as $wide) {
                $width = strlen($wide);
                if (strncmp($value, $wide, $width) === 0) {
                    $value = substr($value, $width);
                }
                if (strlen($value) >= $width
                    && substr($value, -$width) === $wide
                ) {
                    $value = substr($value, 0, strlen($value) - $width);
                }
            }
        } while ($value !== $before);
        return $value;
    }

    /**
     * Quotes wrapping the whole value, removed.
     *
     * One pass: `"'8.8.8.8'"` keeps its inner pair, which is the
     * conservative answer when the alternative is peeling a value that
     * legitimately begins and ends with an apostrophe.
     *
     * @param string $value
     * @return string
     */
    private static function stripWrappingQuotes($value)
    {
        foreach (self::QUOTE_PAIRS as $open => $close) {
            $head = strlen($open);
            $tail = strlen($close);
            if (strlen($value) < $head + $tail) {
                continue;
            }
            if (strncmp($value, $open, $head) === 0
                && substr($value, -$tail) === $close
            ) {
                return substr($value, $head, strlen($value) - $head - $tail);
            }
        }
        return $value;
    }

    /**
     * A defanged value, refanged.
     *
     * Values are **stored** refanged — `ComplexTypeTool` does it on the
     * way in, which is how the freetext importer turns a report's
     * `hxxp://evil[.]com` into an attribute — so a defanged paste that
     * is not refanged here resolves to nothing and the page reports,
     * truthfully and uselessly, that nobody has recorded it.
     *
     * Core's table is therefore read rather than copied: it is the same
     * vocabulary, it already knows forms this file would never have
     * listed (`hxtp`, `meow://`, `h[tt]p`), and a form core learns
     * later is one this page learns with it. Its `types` key is
     * deliberately ignored — every rule is applied to every value,
     * which is exactly what core's own `__refangInput()` does when it
     * has a string and no type, and the position this page is always
     * in.
     *
     * @param string $value
     * @return string
     */
    private static function refang($value)
    {
        foreach (self::REFANG_EXTRA as $from => $to) {
            $value = preg_replace($from, $to, $value);
        }
        foreach (ComplexTypeTool::REFANG_REGEX_TABLE as $regex) {
            $value = preg_replace($regex['from'], $regex['to'], $value);
        }
        return $value;
    }
}
