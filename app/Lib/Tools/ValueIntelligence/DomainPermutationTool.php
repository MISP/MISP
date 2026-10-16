<?php

/**
 * Spellings of a domain that a person could mistake for it.
 *
 * Pure, static, and free of MISP: it takes a label and returns strings.
 * Nothing here reads a model, a database, a setting or a user, which is
 * what lets the near-match section's typosquat engine be *generation*
 * here and *set membership* in the model layer, and lets this file be
 * reasoned about — and tested — on its own.
 *
 * The classes are dnstwist's, minus the ones that need a network or a
 * word list. dnstwist asks *"which of these are registered?"* and pays
 * a DNS lookup per candidate; the engine that calls this asks *"which
 * of these are already in your instance?"*, which is one indexed
 * query. Same generator, different question, and the second one is
 * orders of magnitude cheaper.
 *
 * **Generation is linear in the label's length, not combinatorial.**
 * Every class below is O(n) or O(n·k) over the label, so the candidate
 * set grows with the name rather than exploding: 113 candidates for
 * `foo.com`, 186 for `github.com`, and 1,131 for a label of 63
 * characters, which is the longest DNS allows. There is no cap
 * in this file, and none is needed; what bounds a run is the class
 * list, which a caller can print in full.
 *
 * **What this deliberately does not do.** It does not know a public
 * suffix from a domain label — MISP ships no public-suffix list — so
 * `TLDS` is a hand-picked set of the endings squatters actually buy
 * and the "label" is everything before the last dot. On
 * `www.example.com` that means `www` is permuted too. The extra
 * candidates are noise that costs nothing: a spelling nobody
 * registered simply fails to match.
 *
 * @see ValueIntelligence::typosquatEngine
 */
class DomainPermutationTool
{
    /**
     * The generation classes, ordered by how close the result reads to
     * the original — a dropped character looks more like a typo than a
     * different TLD does — because a caller that ranks rows wants that
     * order and should not have to invent one.
     *
     * The keys are the vocabulary a row carries; the wording a reader
     * sees lives in the view, so this file needs no translator and the
     * strings stay extractable where they are shown.
     */
    const CLASSES = array(
        'omission',
        'repetition',
        'transposition',
        'replacement',
        'insertion',
        'vowel_swap',
        'homoglyph',
        'bitsquat',
        'hyphenation',
        'subdomain',
        'addition',
        'tld_swap',
    );

    /**
     * Keys adjacent on a QWERTY keyboard.
     *
     * The `replacement` and `insertion` classes are about fingers, not
     * about characters: `gitjub.com` is a plausible mistake and
     * `gitzub.com` is not, and the difference is which key sits beside
     * `h`.
     */
    private static $keyboard = array(
        'q' => 'wa', 'w' => 'qeas', 'e' => 'wrsd', 'r' => 'etdf',
        't' => 'ryfg', 'y' => 'tugh', 'u' => 'yihj', 'i' => 'uojk',
        'o' => 'ipkl', 'p' => 'ol', 'a' => 'qwsz', 's' => 'awedxz',
        'd' => 'serfcx', 'f' => 'drtgvc', 'g' => 'ftyhbv',
        'h' => 'gyujnb', 'j' => 'huikmn', 'k' => 'jiolm', 'l' => 'kop',
        'z' => 'asx', 'x' => 'zsdc', 'c' => 'xdfv', 'v' => 'cfgb',
        'b' => 'vghn', 'n' => 'bhjm', 'm' => 'njk',
        '1' => '2q', '2' => '13w', '3' => '24e', '4' => '35r',
        '5' => '46t', '6' => '57y', '7' => '68u', '8' => '79i',
        '9' => '80o', '0' => '9p',
    );

    /**
     * Characters that read as other characters.
     *
     * Only substitutions that are themselves legal in a hostname:
     * `paypa1.com` is a domain somebody can register and this instance
     * can hold, `paypa|.com` is not, and generating the second would
     * spend the candidate slot on a string no row can ever match.
     * Multi-character entries go both ways on purpose — `rn` for `m`
     * is the oldest one in the book.
     */
    private static $homoglyph = array(
        'a' => array('4'),
        'b' => array('6', '8', 'lb'),
        'c' => array('e'),
        'd' => array('cl', 'b'),
        'e' => array('3', 'c'),
        'g' => array('q', '9', '6'),
        'i' => array('1', 'l', 'j'),
        'l' => array('1', 'i'),
        'm' => array('rn', 'nn'),
        'n' => array('m', 'r'),
        'o' => array('0', 'q'),
        'q' => array('g', '9'),
        'rn' => array('m'),
        's' => array('5'),
        'u' => array('v'),
        'v' => array('u'),
        'w' => array('vv'),
        'z' => array('2'),
        '0' => array('o'),
        '1' => array('l', 'i'),
        '5' => array('s'),
    );

    private static $vowels = array('a', 'e', 'i', 'o', 'u');

    /**
     * Endings worth swapping to.
     *
     * Not IANA's 1,440 — that would put the whole class an order of
     * magnitude above every other one and fill a panel with
     * `github.aero`. These are the cheap and the abused: the legacy
     * gTLDs, the ccTLDs that resell freely, and the new gTLDs that
     * turn up in phishing.
     */
    private static $tlds = array(
        'com', 'net', 'org', 'info', 'biz', 'co', 'io', 'me', 'cc',
        'tv', 'online', 'site', 'xyz', 'top', 'club', 'shop', 'app',
        'dev', 'live', 'store', 'icu', 'cn', 'ru', 'de', 'uk', 'eu',
        'fr', 'nl', 'it', 'br',
    );

    /** A DNS label's maximum length, and a name's. */
    const LABEL_MAX = 63;
    const NAME_MAX = 253;

    /**
     * Is this value worth generating spellings for at all?
     *
     * A bare `localhost`, an address, or a name already at the length
     * limit produces either nothing or nothing legal, and asking the
     * database about it would be a query spent on a guaranteed empty
     * answer.
     *
     * @param string $value
     * @return bool
     */
    public static function applies($value)
    {
        $value = strtolower(trim((string)$value));
        if ($value === '' || strlen($value) > self::NAME_MAX) {
            return false;
        }
        if (strpos($value, '.') === false) {
            return false;
        }
        // An address is not a name, and `8.8.8.8` would otherwise
        // generate 200 spellings of a number.
        if (preg_match('/^[0-9.]+$/', $value)) {
            return false;
        }
        return (bool)preg_match('/^[a-z0-9.-]+$/', $value);
    }

    /**
     * Every spelling, keyed by the spelling, valued by its class.
     *
     * Keyed that way because the caller's next move is a set-membership
     * test: it hands the keys to one `IN` query and reads the class
     * back off whatever came home. A candidate reachable two ways —
     * and there are always some — keeps the earliest class in
     * `CLASSES`, so the row says the simplest thing that is true of it.
     *
     * @param string $domain
     * @return array Candidate => class key. Empty if `applies()` is false.
     */
    public static function candidates($domain)
    {
        if (!self::applies($domain)) {
            return array();
        }
        $domain = strtolower(trim($domain));
        $parts = explode('.', $domain);
        $tld = array_pop($parts);
        $label = implode('.', $parts);

        $out = array();
        foreach (self::CLASSES as $class) {
            $set = $class === 'tld_swap'
                ? self::tldSwaps($label, $tld)
                : self::withTld(self::generate($class, $label), $tld);
            foreach ($set as $candidate) {
                if (isset($out[$candidate])
                    || strcasecmp($candidate, $domain) === 0
                    || !self::isLegalName($candidate)
                ) {
                    continue;
                }
                $out[$candidate] = $class;
            }
        }
        return $out;
    }

    /**
     * One class's raw output, before validity and before the TLD.
     *
     * @param string $class One of `CLASSES`
     * @param string $label
     * @return array
     */
    private static function generate($class, $label)
    {
        $n = strlen($label);
        $out = array();
        switch ($class) {
            case 'omission':
                for ($i = 0; $i < $n; $i++) {
                    $out[] = substr($label, 0, $i) . substr($label, $i + 1);
                }
                break;

            case 'repetition':
                for ($i = 0; $i < $n; $i++) {
                    if (ctype_alnum($label[$i])) {
                        $out[] = substr($label, 0, $i) . $label[$i]
                            . substr($label, $i);
                    }
                }
                break;

            case 'transposition':
                for ($i = 0; $i < $n - 1; $i++) {
                    if ($label[$i] === $label[$i + 1]) {
                        continue;
                    }
                    $out[] = substr($label, 0, $i) . $label[$i + 1]
                        . $label[$i] . substr($label, $i + 2);
                }
                break;

            case 'replacement':
                for ($i = 0; $i < $n; $i++) {
                    if (!isset(self::$keyboard[$label[$i]])) {
                        continue;
                    }
                    foreach (str_split(self::$keyboard[$label[$i]]) as $k) {
                        $out[] = substr($label, 0, $i) . $k
                            . substr($label, $i + 1);
                    }
                }
                break;

            case 'insertion':
                /* Not at either end: a character before the first or
                   after the last is the `addition` class, and running
                   both would file the same string under whichever ran
                   first. */
                for ($i = 1; $i < $n - 1; $i++) {
                    if (!isset(self::$keyboard[$label[$i]])) {
                        continue;
                    }
                    foreach (str_split(self::$keyboard[$label[$i]]) as $k) {
                        $out[] = substr($label, 0, $i) . $k
                            . substr($label, $i);
                        $out[] = substr($label, 0, $i + 1) . $k
                            . substr($label, $i + 1);
                    }
                }
                break;

            case 'vowel_swap':
                for ($i = 0; $i < $n; $i++) {
                    if (!in_array($label[$i], self::$vowels, true)) {
                        continue;
                    }
                    foreach (self::$vowels as $v) {
                        if ($v !== $label[$i]) {
                            $out[] = substr($label, 0, $i) . $v
                                . substr($label, $i + 1);
                        }
                    }
                }
                break;

            case 'homoglyph':
                foreach (self::$homoglyph as $from => $tos) {
                    $from = (string)$from;
                    $len = strlen($from);
                    for ($i = 0; $i + $len <= $n; $i++) {
                        if (substr($label, $i, $len) !== $from) {
                            continue;
                        }
                        foreach ($tos as $to) {
                            $out[] = substr($label, 0, $i) . $to
                                . substr($label, $i + $len);
                        }
                    }
                }
                break;

            case 'bitsquat':
                for ($i = 0; $i < $n; $i++) {
                    $ord = ord($label[$i]);
                    for ($bit = 0; $bit < 8; $bit++) {
                        $char = chr($ord ^ (1 << $bit));
                        /*
                         * **Bit 5 is ASCII's case bit**, and neither
                         * DNS nor `attributes.value1` — a
                         * `utf8mb3_unicode_ci` column — can tell
                         * `Github.com` from `github.com`. Flipping it
                         * generates the value itself, the database
                         * matches it, and the panel whose entire
                         * purpose is to say *these two values are not
                         * the same* opens by claiming a value is a
                         * look-alike of itself.
                         */
                        if (strtolower($char) === strtolower($label[$i])) {
                            continue;
                        }
                        if (ctype_alnum($char) || $char === '-') {
                            $out[] = substr($label, 0, $i) . $char
                                . substr($label, $i + 1);
                        }
                    }
                }
                break;

            case 'hyphenation':
            case 'subdomain':
                $join = $class === 'hyphenation' ? '-' : '.';
                for ($i = 1; $i < $n; $i++) {
                    if (!ctype_alnum($label[$i])
                        || !ctype_alnum($label[$i - 1])
                    ) {
                        continue;
                    }
                    $out[] = substr($label, 0, $i) . $join
                        . substr($label, $i);
                }
                break;

            case 'addition':
                foreach (array_merge(range('a', 'z'), range('0', '9'))
                    as $char
                ) {
                    $out[] = $label . $char;
                }
                break;
        }
        return $out;
    }

    /**
     * @param array $labels
     * @param string $tld
     * @return array
     */
    private static function withTld(array $labels, $tld)
    {
        $out = array();
        foreach ($labels as $label) {
            $out[] = $label . '.' . $tld;
        }
        return $out;
    }

    /**
     * @param string $label
     * @param string $tld
     * @return array
     */
    private static function tldSwaps($label, $tld)
    {
        $out = array();
        foreach (self::$tlds as $candidate) {
            if ($candidate !== $tld) {
                $out[] = $label . '.' . $candidate;
            }
        }
        return $out;
    }

    /**
     * Could this string be a hostname somebody registered?
     *
     * The classes generate freely and this is where the illegal ones
     * go: a label cannot start or end with a hyphen, cannot exceed 63
     * characters, cannot be empty — which `omission` and `subdomain`
     * both produce — and the whole name cannot exceed 253. A candidate
     * that no registrar would sell is a candidate no attribute can
     * hold, so keeping it would only widen the `IN` list.
     *
     * @param string $name
     * @return bool
     */
    private static function isLegalName($name)
    {
        if ($name === '' || strlen($name) > self::NAME_MAX) {
            return false;
        }
        $labels = explode('.', $name);
        if (count($labels) < 2) {
            return false;
        }
        foreach ($labels as $label) {
            if ($label === '' || strlen($label) > self::LABEL_MAX) {
                return false;
            }
            if ($label[0] === '-' || substr($label, -1) === '-') {
                return false;
            }
            if (!preg_match('/^[a-z0-9-]+$/', $label)) {
                return false;
            }
        }
        return true;
    }
}
