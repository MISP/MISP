<?php

/**
 * What role a galaxy's clusters play, so a panel can ask for the ones
 * that name a threat without hardcoding a list of galaxy names.
 *
 * MISP records nothing of the kind. `galaxies` carries `type`, `name`,
 * `namespace`, `icon` and `kill_chain_order`, and `namespace` groups by
 * *publisher* — misp, mitre, tidal, disarm, nist-nice — not by what the
 * clusters underneath are for. So the 130 galaxies misp-galaxy ships
 * are, to any consumer, one undifferentiated set in which Threat Actor
 * sits beside UKHSA Culture Collections, Firearms and Cancer.
 *
 * **The answer lives on the galaxy.** misp-galaxy declares `category`
 * and `sub_category` on each definition, `__load_galaxies` ingests them
 * into `galaxies`, and this class reads that column. The vocabulary is
 * misp-galaxy's own, read from its `vocabularies/common` files.
 *
 * An unclassified galaxy is *unrecognised*, not judged harmless, and
 * every caller skips it. That includes a locally created galaxy until an
 * administrator classifies it on `galaxies/add` or `galaxies/edit`.
 *
 * **Why a named threat is a galaxy cluster and nothing else.** Measured
 * on the development instance, 2026-09-03:
 *
 *   freetext tags        10,840 exist, 173 used on events. Ranked by
 *                        event count the top two are the word
 *                        `malware` (165 events) and ` C2` (72), and
 *                        one malware family carries seven spellings
 *                        (`LummaC2`, `Lumma`, `LummaStealer`,
 *                        `lummaC`, ...). A card ranking these leads
 *                        with a category noun and double-counts
 *                        everything it does recognise.
 *   taxonomies           the three that sound like they name threats
 *                        classify instead: `malware_classification`
 *                        by category, `ms-caro-malware` by type and
 *                        platform, `adversary` by infrastructure
 *                        status. The only namespaced tags here that
 *                        do name one — `Threat:Sofacy/APT28`,
 *                        `Banker: TrickBot` — are absent from
 *                        `taxonomies`: freetext with a colon in it.
 *   galaxy clusters      curated, deduplicated, each with a page to
 *                        link to and an ACL to check.
 *
 * Attack patterns are excluded from `named-threat` on purpose: *where
 * in the intrusion* is a different question from *who*, it is answered
 * by its own group on the same card, and it is the single largest
 * galaxy on most values (21 of `8.8.8.8`'s 26 event clusters), so
 * folding it in would bury the names it sits beside.
 *
 * **It takes no `$user`.** A galaxy's category is a property of the
 * definition, the same for every viewer, and a caller only ever asks
 * about a type it is already holding from a label it is already allowed
 * to see.
 */
class GalaxyCategory
{
    /**
     * Clusters that name something conducting or constituting an
     * intrusion. The dividing line is curation, not menace: a
     * surveillance vendor is in because that galaxy is a curated list
     * of firms selling intrusion capability, while `intelligence-agency`
     * is out because it is a reference list of every agency there is.
     */
    const NAMED_THREAT = 'named-threat';

    /** Adversary behaviour — the *where in the intrusion* question. */
    const TECHNIQUE = 'technique';

    /** Who was hit: sector, place, target description. */
    const VICTIM = 'victim';

    /** Mitigations, countermeasures and controls. */
    const DEFENSIVE = 'defensive';

    /** Detection content: rules, analytics, data sources. */
    const DETECTION = 'detection';

    /** What is exposed: assets, platforms, services. */
    const TARGETING = 'targeting';

    /**
     * The near-misses, named so they are not mistaken for oversights.
     * `producer` and `intelligence-agency` are the two that read like
     * threats and are not: the first names who published the
     * intelligence, the second is a directory.
     */
    const CONTEXT = 'context';

    /**
     * A reference list from another domain, carried for sharing rather
     * than to describe an intrusion.
     */
    const REFERENCE = 'reference';

    const ACTOR = 'actor';
    const CAMPAIGN = 'campaign';
    const MALWARE = 'malware';
    const TOOL = 'tool';

    /**
     * The `TECHNIQUE` sub-category whose clusters carry a `kill_chain` element,
     * which is what a tactic roll-up reads. Named because two callers
     * ask for it now — `isAttackPattern` and the tactic chain.
     */
    const ATTACK_PATTERN = 'attack-pattern';

    /** The `DEFENSIVE` sub-category of ATT&CK-style mitigations. */
    const COURSE_OF_ACTION = 'course-of-action';

    /**
     * @var array|null category => array('description' => string,
     *     'sub_categories' => array)
     */
    private static $vocabulary = null;

    /**
     * misp-galaxy's category and sub-category vocabularies, joined on
     * each sub-category's `parent`. Empty outside CakePHP.
     *
     * @return array
     */
    private static function vocabulary()
    {
        if (self::$vocabulary !== null) {
            return self::$vocabulary;
        }
        self::$vocabulary = array();
        if (!defined('APP')) {
            return self::$vocabulary;
        }
        $dir = APP . 'files' . DS . 'misp-galaxy' . DS . 'vocabularies'
            . DS . 'common' . DS;
        $read = function ($file) {
            $raw = @file_get_contents($file);
            $decoded = $raw === false ? null : json_decode($raw, true);
            return is_array($decoded) ? $decoded : array();
        };
        $categories = $read($dir . 'galaxy-category.json');
        $subCategories = $read($dir . 'galaxy-sub-category.json');
        foreach ($categories['values'] ?? array() as $entry) {
            self::$vocabulary[$entry['value']] = array(
                'description' => $entry['description'] ?? '',
                'sub_categories' => array(),
            );
        }
        foreach ($subCategories['values'] ?? array() as $entry) {
            $parent = $entry['parent'] ?? null;
            if (isset(self::$vocabulary[$parent])) {
                self::$vocabulary[$parent]['sub_categories'][]
                    = $entry['value'];
            }
        }
        return self::$vocabulary;
    }

    /**
     * The categories ingested from the galaxy definitions.
     *
     * **Null until something asks**, and empty whenever the answer
     * cannot be had: outside CakePHP, or before the migration adding
     * the columns has run.
     *
     * @var array|null type => array(category, sub_category)
     */
    private static $ingested = null;

    /**
     * @return array type => array(category, sub_category)
     */
    private static function ingested()
    {
        if (self::$ingested !== null) {
            return self::$ingested;
        }
        self::$ingested = array();
        if (!class_exists('ClassRegistry')) {
            return self::$ingested;
        }
        $model = ClassRegistry::init('Galaxy');
        $schema = $model->schema();
        /*
         * Asked of the schema rather than attempted and caught: an
         * instance that has not run the update is the normal state
         * during an upgrade, not an error worth a stack trace in the
         * log every time a value page is drawn.
         */
        if (!isset($schema['category']) || !isset($schema['sub_category'])) {
            return self::$ingested;
        }
        $rows = $model->find('all', array(
            'recursive' => -1,
            'fields' => array('Galaxy.type', 'Galaxy.category',
                'Galaxy.sub_category'),
            'conditions' => array('Galaxy.category !=' => ''),
        ));
        foreach ($rows as $row) {
            $row = $row['Galaxy'];
            if (empty($row['type']) || empty($row['category'])) {
                continue;
            }
            self::$ingested[$row['type']] = array(
                $row['category'],
                empty($row['sub_category']) ? null : $row['sub_category'],
            );
        }
        return self::$ingested;
    }

    /**
     * Drop what was read, so the next call reads again.
     *
     * For a shell that ingests galaxies and then asks about them in
     * the same process, and for a test that changes a row and wants the
     * next call to see it.
     *
     * @return void
     */
    public static function forget()
    {
        self::$ingested = null;
    }

    /**
     * Stand in for the database read, for a caller with no database.
     *
     * @param array $classified type => array(category, sub_category)
     * @return void
     */
    public static function prime(array $classified)
    {
        self::$ingested = $classified;
    }

    /**
     * @param string $galaxyType `galaxies.type`
     * @return array|null category and sub-category, or null if
     *     unrecognised
     */
    public static function of($galaxyType)
    {
        $galaxyType = (string)$galaxyType;
        $known = self::ingested();
        if (!isset($known[$galaxyType])) {
            return null;
        }
        return array(
            'category' => $known[$galaxyType][0],
            'sub_category' => $known[$galaxyType][1],
        );
    }

    /**
     * @param string $galaxyType
     * @return bool False for an unrecognised galaxy
     */
    public static function isNamedThreat($galaxyType)
    {
        $found = self::of($galaxyType);
        return $found !== null
            && $found['category'] === self::NAMED_THREAT;
    }

    /**
     * @param string $galaxyType
     * @return string|null `actor`, `campaign`, `malware`, `tool` for a
     *     named threat; the category's own sub-category otherwise
     */
    public static function subCategoryOf($galaxyType)
    {
        $found = self::of($galaxyType);
        return $found === null ? null : $found['sub_category'];
    }

    /**
     * Whether this galaxy's clusters are ATT&CK-shaped techniques —
     * the ones that carry a `kill_chain` element naming their tactic,
     * and so the ones a tactic roll-up can place.
     *
     * The other two `TECHNIQUE` sub-categories are excluded and each for its own
     * reason. A `tactic` galaxy's clusters *are* tactics, so collapsing
     * them would have a tactic counting itself; a `technique` galaxy is
     * another framework's technique list, whose tactic vocabulary is
     * its own and does not belong on one strip with ATT&CK's.
     *
     * @param string $galaxyType
     * @return bool
     */
    public static function isAttackPattern($galaxyType)
    {
        $found = self::of($galaxyType);
        return $found !== null
            && $found['category'] === self::TECHNIQUE
            && $found['sub_category'] === self::ATTACK_PATTERN;
    }

    /**
     * Every galaxy type of one sub-category, for a caller that has to
     * ask in SQL rather than over rows already read.
     *
     * @param string $subCategory One of the `sub_categories` in the
     *     vocabulary above
     * @return array Galaxy types
     */
    public static function typesOfSubCategory($subCategory)
    {
        $types = array();
        foreach (self::ingested() as $type => $pair) {
            if ($pair[1] === $subCategory) {
                $types[] = $type;
            }
        }
        return $types;
    }

    /**
     * Every galaxy type in one category, for a caller that has to ask
     * in SQL rather than over rows already read.
     *
     * @param string $category One of the constants above
     * @return array Galaxy types
     */
    public static function typesIn($category)
    {
        $types = array();
        foreach (self::ingested() as $type => $pair) {
            if ($pair[0] === $category) {
                $types[] = $type;
            }
        }
        return $types;
    }

    /**
     * The categories, in the order the vocabulary states them.
     *
     * @return array
     */
    public static function categories()
    {
        return array_keys(self::vocabulary());
    }

    /**
     * The sub-categories in use under one category.
     *
     * @param string $category
     * @return array Empty both for `reference`, which has none, and for
     *     a category outside the vocabulary
     */
    public static function subCategoriesIn($category)
    {
        $vocabulary = self::vocabulary();
        if (!isset($vocabulary[$category])) {
            return array();
        }
        return $vocabulary[$category]['sub_categories'];
    }

    /**
     * What a category means, in one line, for a reader choosing one.
     *
     * @param string $category
     * @return string|null
     */
    public static function describe($category)
    {
        $vocabulary = self::vocabulary();
        if (!isset($vocabulary[$category])) {
            return null;
        }
        return $vocabulary[$category]['description'];
    }
}
