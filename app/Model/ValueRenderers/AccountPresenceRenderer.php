<?php

/**
 * Where an identifier has an account, and where it has been exposed.
 *
 * **`socialscan` emits this, free and unauthenticated.** It returns
 * one `user-account` per platform the identifier was found on, with
 * the platform as `account-type` and the identifier itself as the
 * handle — `username` where it was asked for a name, `email` and
 * `user-id` where it was asked for an address. A platform that
 * answered *available*, or that failed, produces no object, so the
 * objects are the hits and nothing else.
 *
 * No `link` is emitted: the module knows a platform holds the account
 * and not where it lives, and a URL guessed from a platform name is a
 * link that sometimes 404s. `accountOf()` reads one where a richer
 * producer sends it.
 *
 * **One object is one platform.** The set is the answer — *found on
 * six of the eleven checked* — so the count is the headline and the
 * platforms are the detail, which is the inverse of most shapes here.
 *
 * **`breach` is absorbed here rather than given a shape of its own**
 * (PRD 1 §3.2, decided 2026-09-18). A breach is where an address was
 * found, which is the question this shape answers; an eighteenth shape
 * would draw a second widget saying the same thing more narrowly and
 * take a slot from the strip to do it. `hibp` and `xposedornot` both
 * emit the template.
 *
 * **The two are counted apart and never summed.** An account is a
 * place the identifier is; a breach is a place it leaked from, and the
 * identifier need not have had an account there at all. `count` stays
 * accounts, because that is what it has always meant and what the
 * strip's *n accounts* reads off; breaches have their own count and
 * their own table.
 *
 * **Breaches arrive in bulk.** Measured against `xposedornot` on one
 * address: 214 breach objects in one answer. So the compact form never
 * lists them, the full form caps what it draws, and the headline is
 * the count plus the one fact that changes what a reader does about
 * it — whether passwords were among what was exposed.
 *
 * **No breach object draws no breach line — never *0 breaches*.** A
 * renderer is handed the objects that matched its templates and
 * nothing else, so a value nobody asked a breach service about and a
 * value a service found nothing on arrive here identically: as an
 * absence. Both modules return an error rather than an empty answer
 * when they find nothing, which means even the run that did happen
 * leaves no object behind. *0 breaches* would therefore be a claim
 * this shape cannot support, and the templates state the count only
 * when there is one to state.
 */
class AccountPresenceRenderer extends ValueRendererBase
{
    public $id = 'account-presence';

    public $templates = array('user-account', 'breach');

    public $compact = 'Values/Renderers/account_presence_compact';

    public $full = 'Values/Renderers/account_presence_full';

    public $eventUse = self::EVENT_SET;

    public function __construct()
    {
        $this->description = __('The platforms an identifier has an'
            . ' account on, and the breaches it appears in.');
    }

    public function matches(array $objects, array $attributes)
    {
        foreach ($objects as $object) {
            if ($this->accountOf($object) !== null
                || $this->breachOf($object) !== null
            ) {
                return true;
            }
        }
        return false;
    }

    public function prepare(array $objects, array $attributes)
    {
        $accounts = array();
        foreach ($objects as $object) {
            $account = $this->accountOf($object);
            if ($account === null) {
                continue;
            }
            /*
             * Deduplicated on the platform and the handle together: an
             * identifier can legitimately have two accounts on one
             * platform, and two modules finding one account is not two
             * accounts.
             */
            $key = strtolower(
                ($account['platform'] ?? '') . "\0"
                . ($account['handle'] ?? '')
            );
            if (isset($accounts[$key])) {
                $held = $accounts[$key]['sources'];
                if (!in_array($account['module'], $held, true)) {
                    $accounts[$key]['sources'][] = $account['module'];
                }
                continue;
            }
            $accounts[$key] = $account;
        }
        $accounts = array_values($accounts);
        $platforms = array();
        foreach ($accounts as $account) {
            $platform = $account['platform'];
            if ($platform !== null
                && !in_array($platform, $platforms, true)
            ) {
                $platforms[] = $platform;
            }
        }
        $breaches = $this->breachesIn($objects);
        return array(
            'accounts' => $accounts,
            'platforms' => $platforms,
            /*
             * Accounts, and only accounts. The strip reads this as
             * *n accounts*, and a breach is not one — see the class
             * docblock.
             */
            'count' => count($accounts),
            'breaches' => $breaches,
            'breach_count' => count($breaches),
            'exposed' => $this->exposedIn($breaches),
            /*
             * The one class that changes what a reader does next, and
             * the reason the compact form has a line to raise its
             * voice on. `Password hints` is a class of its own and is
             * deliberately not this one.
             */
            'passwords' => $this->passwordsIn($breaches),
            'first_breach' => $this->edgeOf($breaches, true),
            'last_breach' => $this->edgeOf($breaches, false),
            'sources' => $this->sources($objects),
        );
    }

    /**
     * @param array $object
     * @return array|null
     */
    private function accountOf(array $object)
    {
        /*
         * Gated on the template rather than left to the field test.
         * `breach` carries a `domain` and a `description` and no
         * account field, so it falls through today — but the two
         * templates now arrive in the same array and a field test that
         * happens to miss is not the same as a rule.
         */
        if (($object['name'] ?? null) !== 'user-account') {
            return null;
        }
        $handle = $this->firstValue($object, array(
            'username', 'email', 'user-id', 'display-name',
        ));
        $platform = $this->value($object, 'account-type');
        if ($handle === null && $platform === null) {
            return null;
        }
        return array(
            'platform' => $platform,
            'handle' => $handle,
            'display' => $this->value($object, 'display-name'),
            'link' => $this->value($object, 'link'),
            'created' => $this->stamp($this->value($object, 'created')),
            'last_login' => $this->stamp(
                $this->value($object, 'last_login')
            ),
            'description' => $this->value($object, 'description'),
            'avatar' => $this->value($object, 'user-avatar'),
            'module' => $object['module'] ?? null,
            'ran_at' => $object['ran_at'] ?? null,
            'sources' => array($object['module'] ?? null),
        );
    }

    /**
     * Every breach in the answer, newest first and deduplicated.
     *
     * Two services reporting the same breach is one breach. The name
     * is what they agree on — the template calls it *stable across its
     * API* and both producers send the service's own identifier — so
     * it is the key, and the services that also reported it become
     * sources the way a second module finding one account does.
     *
     * @param array $objects
     * @return array
     */
    private function breachesIn(array $objects)
    {
        $breaches = array();
        foreach ($objects as $object) {
            $breach = $this->breachOf($object);
            if ($breach === null) {
                continue;
            }
            $key = strtolower($breach['name']);
            if (isset($breaches[$key])) {
                $held = $breaches[$key]['sources'];
                if (!in_array($breach['source'], $held, true)) {
                    $breaches[$key]['sources'][] = $breach['source'];
                }
                continue;
            }
            $breaches[$key] = $breach;
        }
        $breaches = array_values($breaches);
        /*
         * Newest first, and the undated last rather than first: a
         * breach whose date nobody recorded sorts to 0 and would
         * otherwise lead a list whose whole ordering is recency.
         */
        usort($breaches, function ($a, $b) {
            return ($b['at'] ?? 0) <=> ($a['at'] ?? 0);
        });
        return $breaches;
    }

    /**
     * @param array $object
     * @return array|null
     */
    private function breachOf(array $object)
    {
        if (($object['name'] ?? null) !== 'breach') {
            return null;
        }
        /*
         * `name` is the template's one required relation and the key
         * this deduplicates on, so a breach without one is not a row
         * this can draw.
         */
        $name = $this->value($object, 'name');
        if ($name === null) {
            return null;
        }
        $source = $this->value($object, 'source')
            ?? ($object['module'] ?? null);
        return array(
            'name' => $name,
            'title' => $this->value($object, 'title'),
            'domain' => $this->value($object, 'domain'),
            'at' => $this->stamp($this->value($object, 'breach-date')),
            'added' => $this->stamp($this->value($object, 'added-date')),
            /*
             * How many accounts the breach exposed — not how many of
             * them are this value, which is always one.
             */
            'accounts' => $this->number($this->value($object,
                'pwn-count')),
            'classes' => $this->values($object, 'data-classes'),
            'description' => $this->value($object, 'description'),
            'link' => $this->value($object, 'link'),
            'source' => $source,
            /*
             * Tri-state, and the same rule as the breach count: a
             * service that did not say whether it verified the breach
             * has not said it could not. `false` is a denial worth
             * drawing; absent is silence, and drawing *unverified* off
             * it puts a claim in the service's mouth.
             */
            'verified' => $this->tribool($object, 'verified'),
            'sensitive' => $this->tribool($object, 'sensitive'),
            'module' => $object['module'] ?? null,
            'sources' => array($source),
        );
    }

    /**
     * A boolean the producer sent, or null where it sent nothing.
     *
     * @param array $object
     * @param string $relation
     * @return bool|null
     */
    private function tribool(array $object, $relation)
    {
        return $this->value($object, $relation) === null
            ? null
            : $this->flag($object, $relation);
    }

    /**
     * Every distinct class of data exposed, across every breach.
     *
     * Case-folded on the way in because the services disagree about
     * capitalisation of the same class and a reader counting *what was
     * exposed* should not be told `Passwords` and `passwords` twice.
     *
     * @param array $breaches
     * @return array
     */
    private function exposedIn(array $breaches)
    {
        $seen = array();
        foreach ($breaches as $breach) {
            foreach ($breach['classes'] as $class) {
                $key = strtolower(trim($class));
                if ($key !== '' && !isset($seen[$key])) {
                    $seen[$key] = trim($class);
                }
            }
        }
        $out = array_values($seen);
        sort($out);
        return $out;
    }

    /**
     * Whether any breach exposed passwords themselves.
     *
     * Matched exactly rather than by substring: `Password hints` and
     * `Security questions and answers` are their own classes and are
     * weaker facts, and a substring test reads a hint as a password.
     *
     * @param array $breaches
     * @return bool
     */
    private function passwordsIn(array $breaches)
    {
        foreach ($breaches as $breach) {
            foreach ($breach['classes'] as $class) {
                if (strtolower(trim($class)) === 'passwords') {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * The oldest or newest breach date in the set, ignoring the
     * undated — which is an absent date and not an old one.
     *
     * @param array $breaches
     * @param bool $oldest
     * @return int|null
     */
    private function edgeOf(array $breaches, $oldest)
    {
        $edge = null;
        foreach ($breaches as $breach) {
            $at = $breach['at'];
            if ($at === null) {
                continue;
            }
            if ($edge === null
                || ($oldest ? $at < $edge : $at > $edge)
            ) {
                $edge = $at;
            }
        }
        return $edge;
    }
}
