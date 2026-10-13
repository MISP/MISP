<?php

App::uses('ModuleLocality', 'Tools');

/**
 * The profile's enrichment declaration, met with what the instance
 * actually offers.
 *
 * The profile says which modules matter for a type, and the tab
 * arrives with them **ticked, not run**. **A third state** lets a
 * module be marked `auto` and run without a press, where the instance
 * allows it.
 *
 * That needs a record that a module has been asked about a value —
 * `Module` is `useTable = false` — or *"run the declared modules on
 * open"* would mean running them on every open.
 * `value_enrichment_runs` is that record, and the reuse window below
 * is what makes it meaningful.
 *
 * Auto-run is the one thing here that **widens** rather than narrows,
 * which is why it is the one thing an instance has to agree to:
 * `Plugin.ValueIntelligence_enrichment_auto_run`, off by default. A
 * profile resolves user → org → instance default, so an analyst can
 * be running under a document they did not write, and without that
 * gate somebody else's declaration would spend their quota.
 *
 * ## The one sentence the whole mechanism reduces to
 *
 * **A profile can only ever narrow what the instance already offers,
 * and every place the two disagree is stated rather than dropped.**
 *
 * `Module::getEnabledModules()` filters on three things — the
 * instance setting `Plugin.Enrichment_<name>_enabled`, the requested
 * type, and `canUse()`, which is site-admin-always and otherwise
 * requires `Plugin.Enrichment_<name>_restrict` to be empty or to equal
 * the reader's `org_id`. A profile picks from the survivors. It cannot
 * enable a module, cannot widen a restriction, and cannot invent a
 * type. What it *can* do is name something that has since been turned
 * off, reserved for another organisation, removed from the modules
 * build, or that never accepted the type it was filed under — four
 * states, all reachable in normal use, and a profile whose stated
 * policy is not the one in effect is a quiet lie. So each one is a
 * condition with an id and a sentence.
 *
 * ## Keyed by attribute type, resolved as a union
 *
 * `auto_run` is keyed by attribute type because module validity is
 * type-scoped: `getEnabledModules($user, $type)` filters on
 * `meta.module-type` and the tab's own header names the type for
 * exactly this reason. A value is several types — `8.8.8.8` can be
 * both `ip-src` and `ip-dst` — so the declaration resolves to the
 * **union over
 * the types the reader actually holds an occurrence of**,
 * deduplicated, and a module declared under two of them is one
 * selection carrying both.
 *
 * The type a selection would run under is the **declared** one where
 * the module accepts it, not the value's most common: the analyst
 * filing `virustotal` under `ip-dst` said which question they wanted
 * asked. It falls back to the row's own default type when the
 * declaration cannot be honoured.
 *
 * ## Locality is a badge, not a gate
 *
 * `ModuleLocality` says whether asking a module tells somebody outside
 * the instance, and the tab shows it per module, because a reader
 * deciding whether to press run is owed that. It withholds nothing.
 *
 * **There is no locality posture.** A posture would gate the one thing
 * that never needs gating: a module not marked `auto` runs only on a
 * press, so a module arriving unticked and a module arriving ticked
 * both send exactly nothing until the reader acts, and the setting
 * would buy a whole vocabulary of refusal in exchange for saving a
 * click. `never` is the reader refusing a module outright, and it is
 * enforced where a run happens. A stored `locality_posture` or
 * `cost_posture` key is ignored rather than migrated: it selects
 * nothing, so there is nothing to carry.
 *
 * ## `max_age_hours` is the reuse window
 *
 * How old a kept answer may be before the module is asked again. A
 * row younger than this is served rather than re-asked.
 *
 * **It bounds automatic reuse only.** A press always asks again: the
 * window is what the page does on its own, and a reader who pressed a
 * button has made a decision a cache must not overrule.
 *
 * No `$user`, no model, no view: the arithmetic and the vocabulary,
 * nothing else, so the tab, the editor and anything later read the
 * same answer.
 */
class ValueEnrichmentTool
{
    /**
     * The run states a declaration may put a module in.
     *
     * `ticked` is what a bare list means. `never` is the profile
     * refusing a module outright, and is a setting that has to be
     * enforced where a run happens rather than
     * where a box is drawn. `auto` runs without one, and is the only
     * state that adds rather than removes — so it is the only one an
     * instance has to permit before it does anything. Where it does
     * not, `auto` behaves as `ticked` and the tab says why.
     */
    const STATE_TICKED = 'ticked';
    const STATE_NEVER = 'never';
    const STATE_AUTO = 'auto';

    /** The reuse window a store would honour. */
    const DEFAULT_MAX_AGE_HOURS = 24;

    /**
     * The stated conditions, one id per way a declaration and an
     * instance can disagree. Ids rather than sentences because the
     * editor states the same conditions in a different place and must
     * not paraphrase them differently.
     */
    const C_SERVICE = 'service.unreachable';
    const C_NOT_OFFERED = 'module.not_offered';
    const C_DISABLED = 'module.disabled';
    const C_RESTRICTED = 'module.restricted';
    const C_TYPE_MISMATCH = 'module.type_mismatch';
    const C_UNRESOLVED = 'module.unresolved';
    const C_TYPE_UNUSED = 'type.unused';
    const C_STATE_NEVER = 'state.never';
    /*
     * Two conditions for an `auto` that will not run, because the
     * reader can act on one of them and not on the other: an instance
     * that has the gate off is a
     * conversation with an administrator, and a gate set to site
     * admins only is not.
     */
    const C_STATE_AUTO_DISABLED = 'state.auto_disabled';
    const C_STATE_AUTO_SITE_ADMIN = 'state.auto_site_admin';

    /**
     * `Plugin.ValueIntelligence_enrichment_auto_run`.
     *
     * The profile says *which* modules; this says *whether any of them
     * may run here*. It has to sit above the profile because
     * `AnalystProfile::resolveFor()` resolves user → org → instance
     * default, so an analyst can be running under a profile they did
     * not author — and the objection to `auto` is precisely that it
     * would make such a profile cause outbound requests on their
     * behalf.
     *
     * `site_admin` exists so an administrator can try the feature on a
     * live instance without conscripting their analysts into it.
     */
    const GATE_OFF = 'off';
    const GATE_SITE_ADMIN = 'site_admin';
    const GATE_ON = 'on';

    /**
     * The claim a stored row carries while its module is being asked.
     *
     * The vocabulary lives here rather than on `ValueEnrichmentRun`
     * for the reason the rest of it does: this class is what the tab,
     * the editor and the model all read, and a word defined in the
     * model would be a word the tool had to import a model to know.
     */
    const RUN_RUNNING = 'running';

    /**
     * The `enrichment` section, whichever shape the profile arrived
     * in.
     *
     * `ValueTrustTool::section()`'s twin, duplicated for the reason
     * that one is: this class is pure and a caller may hand over the
     * parameters alone.
     *
     * @param array|null $profile An `AnalystProfile` row, unwrapped,
     *                            or its `parameters`
     * @return array
     */
    public static function section($profile)
    {
        if (!is_array($profile)) {
            return array();
        }
        if (isset($profile['AnalystProfile'])) {
            $profile = $profile['AnalystProfile'];
        }
        if (isset($profile['parameters'])
            && is_array($profile['parameters'])
        ) {
            $profile = $profile['parameters'];
        }
        return isset($profile['enrichment'])
            && is_array($profile['enrichment'])
            ? $profile['enrichment']
            : array();
    }

    /**
     * The declaration, normalised once.
     *
     * Everything a hand-edited JSON document can get wrong is absorbed
     * here and nowhere else: a type key holding a bare string rather
     * than a list, a null, a name repeated, whitespace around a name,
     * a state that is not one of the three. None of them is an
     * error — a profile is data an analyst edits with a text editor,
     * and the failure mode of strictness is a page that will not
     * render.
     *
     * A module name is matched **exactly** downstream, because
     * `Plugin.Enrichment_<name>_enabled` is exact and a helpfully
     * corrected name would be this class quietly enabling something
     * the profile did not name. A near-miss becomes a stated condition
     * instead (`C_NOT_OFFERED`).
     *
     * @param array|null $profile
     * @return array
     */
    public static function planFor($profile)
    {
        $section = self::section($profile);
        $autoRun = array();
        $declared = array();
        $raw = isset($section['auto_run']) && is_array($section['auto_run'])
            ? $section['auto_run']
            : array();
        foreach ($raw as $type => $names) {
            $type = trim((string)$type);
            if ($type === '') {
                continue;
            }
            if (is_string($names)) {
                $names = array($names);
            }
            if (!is_array($names)) {
                continue;
            }
            /*
             * Two shapes arrive here. `[name, name]` is the older one
             * and means *every one of these is ticked*;
             * `{name: state}` is the current one.
             * A list entry is a value with an integer key, so the two
             * are told apart per entry rather than per type — a
             * hand-edited document can mix them.
             */
            $clean = array();
            foreach ($names as $key => $value) {
                if (is_int($key)) {
                    $name = $value;
                    $state = self::STATE_TICKED;
                } else {
                    $name = $key;
                    $state = $value;
                }
                if (!is_string($name) && !is_numeric($name)) {
                    continue;
                }
                $name = trim((string)$name);
                if ($name === '' || isset($clean[$name])) {
                    continue;
                }
                $clean[$name] = in_array($state, self::states(), true)
                    ? $state
                    : self::STATE_TICKED;
                if (!isset($declared[$name])) {
                    $declared[$name] = array();
                }
                $declared[$name][] = $type;
            }
            $autoRun[$type] = $clean;
        }
        $roles = isset($section['roles']) && is_array($section['roles'])
            ? $section['roles']
            : array();
        return array(
            'auto_run' => $autoRun,
            'declared' => $declared,
            // Per module, `enrichment` or `other`, over ModuleRole's list.
            'roles' => $roles,
            /*
             * Which visualisations this profile wants promoted, best
             * first. It is a ranking of *shapes* rather than of
             * modules on purpose: a profile then holds about a dozen
             * stable entries instead of tracking every module name in
             * the build, and it survives a module being replaced by
             * another that answers the same question.
             *
             * Empty on every profile that says nothing, which is the
             * shipped default — a promotion order is an opinion, and
             * the neutral document has none. What draws then is the
             * shipped per-type order, which lives in code beside the
             * renderers for the same reason.
             */
            'shapes' => self::shapesOf($section),
            /*
             * The reuse window: `value_enrichment_runs` holds what a
             * module last said, and a row younger than this is served
             * rather than re-asked. It bounds *automatic* reuse only
             * — a press is a decision and always re-runs.
             */
            'max_age_hours' => self::maxAgeHours($section),
            /*
             * The switch, and the same one `ValueTrustTool` uses: an
             * empty declaration takes the mechanism out of the path
             * entirely rather than resolving to an empty answer. A
             * profile that names no module produces no selection and
             * **no conditions** — empty means as before, which for
             * this section means the same tab a reader with no
             * enrichment declaration gets.
             */
            'in_force' => !empty($declared),
        );
    }

    /**
     * The shape ranking, normalised the same tolerant way everything
     * else here is.
     *
     * A bare string is one shape, because a document naming a single
     * one reads better written that way and refusing it would be
     * strictness with no benefit. Repeats collapse rather than
     * erroring — a shape ranked twice means it is wanted, once.
     *
     * **An unknown name is kept.** Whether a shape exists is a
     * question about this instance and not about this document: a
     * profile written where a custom renderer is installed must
     * survive being imported where it is not, and come back intact if
     * it is exported again. What the instance does with a name it
     * cannot draw is say so — in the editor at declaration time, and
     * by leaving the slot unfilled at read time.
     *
     * @param array $section
     * @return array Shape ids, in the profile's order
     */
    private static function shapesOf(array $section)
    {
        $raw = isset($section['shapes']) ? $section['shapes'] : null;
        if (is_string($raw)) {
            $raw = array($raw);
        }
        if (!is_array($raw)) {
            return array();
        }
        $out = array();
        foreach ($raw as $shape) {
            if (!is_string($shape) && !is_numeric($shape)) {
                continue;
            }
            $shape = trim((string)$shape);
            if ($shape !== '' && !in_array($shape, $out, true)) {
                $out[] = $shape;
            }
        }
        return $out;
    }

    /**
     * Every state a declaration may name, whether or not it is
     * implemented — a stored state is a valid document and must not be
     * normalised away, or adding the behaviour later means migrating
     * twice.
     *
     * @return array
     */
    public static function states()
    {
        return array(
            self::STATE_TICKED,
            self::STATE_NEVER,
            self::STATE_AUTO,
        );
    }

    /**
     * The states that do what they say.
     *
     * All three. The editor offers only what is implemented, and this
     * is the list it reads that from.
     *
     * @return array
     */
    public static function statesBuilt()
    {
        return self::states();
    }

    /**
     * The gate, normalised. Anything unrecognised reads as `off`.
     *
     * Unrecognised means *off* rather than *on* for the one reason
     * that matters about this setting: every other direction of error
     * costs a click, and this one spends the instance's quota and
     * tells a third party somebody is looking at a value.
     *
     * @param mixed $gate `Configure::read` of the setting
     * @return string
     */
    public static function normaliseGate($gate)
    {
        $gate = is_string($gate) ? trim($gate) : '';
        return in_array(
            $gate,
            array(self::GATE_SITE_ADMIN, self::GATE_ON),
            true
        ) ? $gate : self::GATE_OFF;
    }

    /**
     * Whether this reader may have modules run without pressing.
     *
     * @param mixed $gate
     * @param bool $isSiteAdmin
     * @return bool
     */
    public static function gateAllows($gate, $isSiteAdmin)
    {
        $gate = self::normaliseGate($gate);
        if ($gate === self::GATE_ON) {
            return true;
        }
        return $gate === self::GATE_SITE_ADMIN && !empty($isSiteAdmin);
    }

    /**
     * The state a declaration puts one module in for one type.
     *
     * `ticked` where the profile says nothing, because a module the
     * profile never named is not refused by it — the instance decides
     * that, and this section may only ever narrow.
     *
     * **That default is about refusal, not about the checkbox.** This
     * is what `refuses()` reads, and `never` is the only answer it
     * acts on. Whether a box arrives ticked is decided elsewhere: the
     * rail ticks the names in `resolve()`'s `selected`, which holds
     * only what the profile declared, so an unnamed module arrives
     * **unticked** however this reads. Do not use it to answer *does
     * this arrive ticked* — editor labels built on it would say the
     * opposite of what the tab does.
     *
     * @param array $plan From planFor
     * @param string $name
     * @param string|null $type
     * @return string
     */
    public static function stateFor(array $plan, $name, $type)
    {
        if ($type === null
            || !isset($plan['auto_run'][$type][$name])
        ) {
            return self::STATE_TICKED;
        }
        return $plan['auto_run'][$type][$name];
    }

    /**
     * Whether this declaration refuses a run of this module for this
     * type — the check `ValueIntelligence::enrichmentRun()` has to make,
     * because the run endpoint takes a module name from the request
     * and a disabled checkbox is not a guard.
     *
     * @param array $plan From planFor
     * @param string $name
     * @param string|null $type
     * @return bool
     */
    public static function refuses(array $plan, $name, $type)
    {
        return self::stateFor($plan, $name, $type) === self::STATE_NEVER;
    }

    /**
     * @param array $section
     * @return int
     */
    private static function maxAgeHours(array $section)
    {
        if (!isset($section['max_age_hours'])
            || !is_numeric($section['max_age_hours'])
        ) {
            return self::DEFAULT_MAX_AGE_HOURS;
        }
        $hours = (int)$section['max_age_hours'];
        return $hours > 0 ? $hours : self::DEFAULT_MAX_AGE_HOURS;
    }

    /**
     * The declared modules that apply to the types this reader holds,
     * each with the declaring types in the value's own order.
     *
     * A value with several types resolves the union, deduplicated.
     * Ordered by the value's types rather than
     * by the profile's keys, so the type a run would use is the one
     * the reader's own occurrences make most likely to be meaningful
     * when several were declared.
     *
     * @param array $plan From planFor
     * @param array $types The value's types: `typesFor` rows or plain
     *                     type strings
     * @return array name => list of types
     */
    public static function declaredFor(array $plan, array $types)
    {
        $held = self::typeNames($types);
        $out = array();
        foreach ($held as $type) {
            if (empty($plan['auto_run'][$type])) {
                continue;
            }
            foreach ($plan['auto_run'][$type] as $name => $state) {
                if (!isset($out[$name])) {
                    $out[$name] = array();
                }
                if (!in_array($type, $out[$name], true)) {
                    $out[$name][] = $type;
                }
            }
        }
        ksort($out);
        return $out;
    }

    /**
     * Whether the caller has to go and ask the modules service for the
     * full list before `resolve()` can explain itself.
     *
     * The catalogue the tab already builds is the **enabled and usable
     * and type-matching** set, so a declared module missing from it is
     * missing for one of four reasons and the difference is not in
     * hand. Finding out costs one more local `GET /modules`, and this
     * method exists so that it is paid **only when a condition needs
     * explaining**, which on the shipped default (nothing declared) is
     * never.
     *
     * @param array $plan From planFor
     * @param array $types The value's types
     * @param array $eligible The catalogue's module rows
     * @return array The declared names that need explaining
     */
    public static function needsFacts(array $plan, array $types,
        array $eligible
    ) {
        if (empty($plan['in_force'])) {
            return array();
        }
        $have = array();
        foreach ($eligible as $row) {
            if (isset($row['name'])) {
                $have[$row['name']] = true;
            }
        }
        $missing = array();
        foreach (self::declaredFor($plan, $types) as $name => $ignored) {
            if (!isset($have[$name])) {
                $missing[] = $name;
            }
        }
        return $missing;
    }

    /**
     * The declaration met with the instance: what to tick, what the
     * reader refused, and every place the two disagree.
     *
     * @param array $plan From planFor
     * @param array $facts `service.reachable`, `types`, `eligible`
     *                     (the catalogue's rows), and — only when
     *                     `needsFacts()` asked for them — `modules`
     *                     (name => `present`, `enabled`, `restricted`,
     *                     `restrict_org`, `accepts`) and `offered`
     *                     (every name the service listed)
     * @return array
     */
    public static function resolve(array $plan, array $facts)
    {
        $autoAllowed = self::gateAllows(
            isset($facts['auto_gate']) ? $facts['auto_gate'] : null,
            !empty($facts['site_admin'])
        );
        $out = array(
            'in_force' => !empty($plan['in_force']),
            'max_age_hours' => $plan['max_age_hours'],
            /*
             * Set before the early return below, because `in_force`
             * is about the *module* declaration: a profile that ranks
             * shapes and names no module is a perfectly ordinary
             * document — it says which answers to draw first and lets
             * the instance decide which modules are offered — and
             * losing its ranking here would silently fall the strip
             * back to the shipped order.
             */
            'shapes' => isset($plan['shapes']) ? $plan['shapes'] : array(),
            'auto_gate' => self::normaliseGate(
                isset($facts['auto_gate']) ? $facts['auto_gate'] : null
            ),
            'auto_allowed' => $autoAllowed,
            'declared' => 0,
            'applicable' => 0,
            'selected' => array(),
            'refused' => array(),
            'conditions' => array(),
        );
        if (empty($plan['in_force'])) {
            return $out;
        }
        $out['declared'] = count($plan['declared']);

        $types = self::typeNames(
            isset($facts['types']) ? $facts['types'] : array()
        );
        $out['conditions'] = self::unusedTypes($plan, $types);

        $declared = self::declaredFor($plan, $types);
        $out['applicable'] = count($declared);
        if (empty($declared)) {
            return $out;
        }

        $reachable = !isset($facts['service']['reachable'])
            || !empty($facts['service']['reachable']);
        if (!$reachable) {
            /*
             * One condition, not one per module. Nothing about the
             * declaration is knowable this visit — which is a fact
             * about the service and not about the modules, the same
             * distinction the tab's own empty state makes.
             */
            $out['conditions'][] = self::condition(
                self::C_SERVICE,
                null,
                array_keys($declared),
                __(
                    'The modules service did not answer, so none of'
                    . ' these could be checked against what this'
                    . ' instance offers. Nothing has been selected and'
                    . ' nothing has been sent anywhere.'
                )
            );
            return $out;
        }

        $eligible = array();
        foreach (self::rows($facts, 'eligible') as $row) {
            if (isset($row['name'])) {
                $eligible[$row['name']] = $row;
            }
        }
        $moduleFacts = isset($facts['modules'])
            && is_array($facts['modules'])
            ? $facts['modules']
            : array();
        $offered = isset($facts['offered']) && is_array($facts['offered'])
            ? $facts['offered']
            : array();

        foreach ($declared as $name => $decTypes) {
            if (!isset($eligible[$name])) {
                $out['conditions'][] = self::explain(
                    $name,
                    $decTypes,
                    isset($moduleFacts[$name])
                        ? $moduleFacts[$name]
                        : null,
                    $offered
                );
                continue;
            }
            $locality = self::localityOf($eligible[$name], $name);
            $runType = self::runType($eligible[$name], $decTypes);
            $state = self::stateFor($plan, $name, $runType);
            $entry = array(
                'name' => $name,
                'type' => $runType,
                'declared_for' => $decTypes,
                'state' => $state,
                'locality' => $locality['locality'],
                'locality_source' => $locality['source'],
            );
            if ($state === self::STATE_NEVER) {
                $out['refused'][] = $entry;
                $out['conditions'][] = self::condition(
                    self::C_STATE_NEVER,
                    $name,
                    $decTypes,
                    sprintf(
                        __('Your profile says never run %s. It is not'
                            . ' selected here and a run of it is'
                            . ' refused, not just unticked.'),
                        $name
                    )
                );
                continue;
            }
            $out['selected'][] = $entry;
        }
        /*
         * One note for every `auto` the gate is holding back, not one
         * each: they are all held for the same reason and it is not
         * about any particular module.
         *
         * When the gate allows them there is no condition at all —
         * they simply run, and the rail says so per row.
         */
        $autos = array();
        foreach ($out['selected'] as $entry) {
            if ($entry['state'] === self::STATE_AUTO) {
                $autos[] = $entry['name'];
            }
        }
        if (!empty($autos) && !$autoAllowed) {
            $out['conditions'][] = $out['auto_gate'] === self::GATE_SITE_ADMIN
                ? self::condition(
                    self::C_STATE_AUTO_SITE_ADMIN,
                    null,
                    $autos,
                    sprintf(
                        __n(
                            'Your profile asks for %s to run on its own.'
                            . ' This instance allows that for site'
                            . ' administrators only, so it arrives ticked'
                            . ' and a run still takes a press.',
                            'Your profile asks for %s to run on their own.'
                            . ' This instance allows that for site'
                            . ' administrators only, so they arrive ticked'
                            . ' and a run still takes a press.',
                            count($autos)
                        ),
                        implode(', ', $autos)
                    )
                )
                : self::condition(
                    self::C_STATE_AUTO_DISABLED,
                    null,
                    $autos,
                    sprintf(
                        __n(
                            'Your profile asks for %s to run on its own.'
                            . ' This instance does not allow enrichment to'
                            . ' run without a press, so it arrives ticked'
                            . ' and a run still takes one.',
                            'Your profile asks for %s to run on their own.'
                            . ' This instance does not allow enrichment to'
                            . ' run without a press, so they arrive ticked'
                            . ' and a run still takes one.',
                            count($autos)
                        ),
                        implode(', ', $autos)
                    )
                );
        }
        return $out;
    }

    /**
     * The types a profile declares for that this reader holds no
     * occurrence of.
     *
     * One condition listing all of them rather than one each: a
     * profile written for `ip-src`, `ip-dst`, `domain` and `md5` will
     * have three unused types on most values, and three sentences
     * saying the same thing is noise where one is information. It is
     * stated at all because a declaration for a type the value does
     * not have is a condition, not a quiet omission.
     *
     * @param array $plan
     * @param array $types The value's type names
     * @return array
     */
    private static function unusedTypes(array $plan, array $types)
    {
        $unused = array();
        foreach ($plan['auto_run'] as $type => $names) {
            if (empty($names) || in_array($type, $types, true)) {
                continue;
            }
            $unused[] = $type;
        }
        if (empty($unused)) {
            return array();
        }
        return array(self::condition(
            self::C_TYPE_UNUSED,
            null,
            $unused,
            sprintf(
                __n(
                    'Your profile also names modules for %s, which'
                    . ' this value is not — nothing was matched from'
                    . ' it.',
                    'Your profile also names modules for %s, which'
                    . ' this value is none of — nothing was matched'
                    . ' from them.',
                    count($unused)
                ),
                implode(', ', $unused)
            )
        ));
    }

    /**
     * Why a declared module is not on the rail.
     *
     * Four states and a fifth that should be unreachable, in the order
     * `Module::getEnabledModules()` itself applies them, so the
     * sentence a reader gets is the first thing that actually stopped
     * the module rather than the most interesting one.
     *
     * The unreachable fifth is `C_UNRESOLVED`, and it is a real branch
     * rather than a defensive one: a caller that skips `needsFacts()`
     * lands here, and a page saying *"not available, and I did not
     * find out why"* is honest where a page picking one of the four
     * reasons at random is not.
     *
     * @param string $name
     * @param array $decTypes
     * @param array|null $facts
     * @param array $offered
     * @return array
     */
    private static function explain($name, array $decTypes, $facts,
        array $offered
    ) {
        if (!is_array($facts)) {
            $near = self::nearMiss($name, $offered);
            if (!empty($offered) && !in_array($name, $offered, true)) {
                return self::notOffered($name, $decTypes, $near);
            }
            return self::condition(
                self::C_UNRESOLVED,
                $name,
                $decTypes,
                __(
                    'Your profile names this module and it is not'
                    . ' available for this value. Why was not'
                    . ' established.'
                )
            );
        }
        if (empty($facts['present'])) {
            return self::notOffered(
                $name,
                $decTypes,
                self::nearMiss($name, $offered)
            );
        }
        if (empty($facts['enabled'])) {
            return self::condition(
                self::C_DISABLED,
                $name,
                $decTypes,
                __(
                    'Your profile names this module and this instance'
                    . ' has it turned off. An administrator enables it'
                    . ' under Plugin settings; until then the'
                    . ' declaration stands and does nothing.'
                )
            );
        }
        if (!empty($facts['restricted'])) {
            return self::condition(
                self::C_RESTRICTED,
                $name,
                $decTypes,
                __(
                    'Your profile names this module and this instance'
                    . ' reserves it for one organisation, which is not'
                    . ' yours. A profile shared to an organisation'
                    . ' reaches readers this applies to and readers it'
                    . ' does not.'
                )
            );
        }
        $accepts = isset($facts['accepts']) && is_array($facts['accepts'])
            ? $facts['accepts']
            : array();
        if (!empty($accepts)) {
            return self::condition(
                self::C_TYPE_MISMATCH,
                $name,
                $decTypes,
                sprintf(
                    __(
                        'Your profile files this module under %1$s and'
                        . ' the module does not accept it. It accepts'
                        . ' %2$s.'
                    ),
                    implode(', ', $decTypes),
                    implode(', ', $accepts)
                )
            );
        }
        return self::condition(
            self::C_UNRESOLVED,
            $name,
            $decTypes,
            __(
                'Your profile names this module and it is not'
                . ' available for this value. Why was not established.'
            )
        );
    }

    /**
     * @param string $name
     * @param array $decTypes
     * @param string|null $near
     * @return array
     */
    private static function notOffered($name, array $decTypes, $near)
    {
        $note = __(
            'Your profile names this module and this instance does not'
            . ' offer one by that name — a module build without it, or'
            . ' a name that has changed.'
        );
        if ($near !== null) {
            $note .= ' ' . sprintf(
                __('It does offer %s.'),
                $near
            );
        }
        return self::condition(
            self::C_NOT_OFFERED,
            $name,
            $decTypes,
            $note
        );
    }

    /**
     * An offered module whose name differs from the declared one only
     * in case.
     *
     * Named, never substituted. `Plugin.Enrichment_<name>_enabled` is
     * an exact key, so treating `VirusTotal` as `virustotal` would be
     * this class enabling a module the profile did not name — and the
     * reader can fix a typo in one edit once they can see it.
     *
     * @param string $name
     * @param array $offered
     * @return string|null
     */
    private static function nearMiss($name, array $offered)
    {
        foreach ($offered as $candidate) {
            if (strcasecmp((string)$candidate, (string)$name) === 0
                && (string)$candidate !== (string)$name
            ) {
                return (string)$candidate;
            }
        }
        return null;
    }

    /**
     * The row's locality, and only the map's when the row has none.
     *
     * **One fact, one producer.** The catalogue row already carries
     * this — the rail chips it and the tray counts it — and computing
     * it a second time here would be the page's oldest hazard in a new
     * place: a number in one part of the frame fed by a different code
     * path from the panel it summarises. So the chip on the
     * rail and the count in the tray are literally the same value.
     *
     * The fall-back is for a caller with no catalogue — the editor
     * resolves a declaration against no value at all.
     *
     * @param array $row A catalogue row
     * @param string $name
     * @return array
     */
    private static function localityOf(array $row, $name)
    {
        if (!empty($row['locality'])) {
            return array(
                'locality' => $row['locality'],
                'source' => isset($row['locality_source'])
                    ? $row['locality_source']
                    : ModuleLocality::SOURCE_UNKNOWN,
            );
        }
        return ModuleLocality::resolve($name);
    }

    /**
     * The type a selection would run under: the declared one where the
     * module accepts it, else the row's own default.
     *
     * The declared type wins because it is a statement — an analyst
     * filing `virustotal` under `ip-dst` asked for that question — and
     * the row's default is `typesFor`'s most-common, which is a fact
     * about the data rather than about the analyst.
     *
     * @param array $row A catalogue row
     * @param array $decTypes
     * @return string|null
     */
    private static function runType(array $row, array $decTypes)
    {
        $accepts = isset($row['types']) && is_array($row['types'])
            ? $row['types']
            : array();
        foreach ($decTypes as $type) {
            if (isset($accepts[$type])) {
                return $type;
            }
        }
        return isset($row['type']) ? $row['type'] : null;
    }

    /**
     * @param string $id
     * @param string|null $module
     * @param array $subjects Types, or module names for `C_SERVICE`
     * @param string $note
     * @return array
     */
    private static function condition($id, $module, array $subjects,
        $note
    ) {
        return array(
            'id' => $id,
            'module' => $module,
            'subjects' => $subjects,
            'note' => $note,
        );
    }

    /**
     * `typesFor` rows or plain strings, in the order given.
     *
     * @param array $types
     * @return array
     */
    private static function typeNames(array $types)
    {
        $out = array();
        foreach ($types as $row) {
            if (is_array($row)) {
                $row = isset($row['type']) ? $row['type'] : null;
            }
            if (!is_string($row) && !is_numeric($row)) {
                continue;
            }
            $row = (string)$row;
            if ($row !== '' && !in_array($row, $out, true)) {
                $out[] = $row;
            }
        }
        return $out;
    }

    /**
     * Whether a stored row is still inside a reuse window.
     *
     * The window is the *reader's*, read from their own profile, while
     * the row belongs to their organisation. Two analysts in one org
     * can therefore hold different windows over one row, and that
     * resolves correctly rather than merely tolerably: the shorter
     * window re-runs, and the refreshed row then serves the longer
     * one, so nobody is served a result older than their own profile
     * allows.
     *
     * @param array $row A `value_enrichment_runs` row
     * @param int $maxAgeHours
     * @return bool
     */
    public static function isFresh(array $row, $maxAgeHours)
    {
        if (empty($row['last_run'])) {
            return false;
        }
        return (time() - (int)$row['last_run']) < ($maxAgeHours * 3600);
    }

    /**
     * Whether a stored row is a claim that has not aged out.
     *
     * @param array $row
     * @param int $timeout Seconds a module is allowed to take
     * @return bool
     */
    public static function isInFlight(array $row, $timeout)
    {
        if (empty($row['state']) || $row['state'] !== self::RUN_RUNNING) {
            return false;
        }
        return (time() - (int)$row['last_run']) < $timeout;
    }

    /**
     * What the page should fire, and what it already knows.
     *
     * The arithmetic behind the plan the panel carries, and pure like
     * everything else here: the caller hands over the resolution, the
     * organisation's stored rows and the timeout, and this decides one
     * disposition per declared `auto` module.
     *
     * Four dispositions, and the ordering between them is the whole
     * content of the function:
     *
     * | | |
     * |---|---|
     * | `blocked` | the gate, or anything that stopped it resolving |
     * | `in_flight` | somebody is asking right now |
     * | `fresh` | a row inside the reader's own reuse window |
     * | `fire` | no row, or one past that window |
     *
     * `blocked` is tested first because a module the gate is holding
     * must not be described by the store — *"asked 2 h ago"* against a
     * module this instance will not run on its own is answering a
     * question nobody asked. `in_flight` precedes `fresh` because a
     * claim carries no result to be fresh with.
     *
     * @param array $resolved From `resolve()`
     * @param array $stored `module|type` => row, from the run model
     * @param int $timeout Seconds a module is allowed to take
     * @return array One entry per declared `auto` module
     */
    public static function autoDispositions(array $resolved,
        array $stored, $timeout
    ) {
        $out = array();
        if (empty($resolved['in_force'])) {
            return $out;
        }
        $maxAge = $resolved['max_age_hours'];
        $allowed = !empty($resolved['auto_allowed']);
        foreach ($resolved['selected'] as $entry) {
            if ($entry['state'] !== self::STATE_AUTO) {
                continue;
            }
            $key = $entry['name'] . '|' . $entry['type'];
            $row = isset($stored[$key]) ? $stored[$key] : null;
            if (!$allowed) {
                $how = 'blocked';
            } elseif ($row !== null && self::isInFlight($row, $timeout)) {
                $how = 'in_flight';
            } elseif ($row !== null
                && $row['state'] !== self::RUN_RUNNING
                && self::isFresh($row, $maxAge)
            ) {
                $how = 'fresh';
            } else {
                $how = 'fire';
            }
            $out[] = array(
                'module' => $entry['name'],
                'type' => $entry['type'],
                'locality' => $entry['locality'],
                'disposition' => $how,
                /*
                 * Age and counts, never `user_id`. The Overview
                 * badge consumes this response too, and a field that
                 * is not here cannot be drawn there by accident.
                 */
                'age' => $row === null || empty($row['last_run'])
                    ? null
                    : (time() - (int)$row['last_run']),
                'last_state' => $row === null ? null : $row['state'],
                'total' => $row === null ? null : (int)$row['total'],
                'shown' => $row === null ? null : (int)$row['shown'],
            );
        }
        return $out;
    }

    /**
     * How many returned elements still read as an answer rather than
     * as a set.
     *
     * Above this a module's response is summarised by its size: a
     * reader cannot act on three relations picked out of a thousand
     * passive-DNS records, because which three is an accident of
     * ordering. Below it the cap does the bounding and every chip is
     * about the whole answer.
     *
     * Eight rather than three. `mmdb_lookup` answers with four objects,
     * and the rule that a chip skips a very long value is justified by
     * `mmdb_lookup`'s own `text` relation — which only bites if that
     * module is drawing relations at all. Three would summarise the one
     * module whose relations are named as the place a map later slots
     * into.
     */
    const CHIP_FEW = 8;

    /** Chips drawn per module before the rest become a `+N`. */
    const CHIP_CAP = 3;

    /**
     * The longest value a chip will carry.
     *
     * A chip is not a paragraph. `mmdb_lookup`'s `text` relation is
     * `db_source: GeoOpen-Country-20250115...`, a sentence about where
     * an answer came from rather than the answer.
     */
    const CHIP_VALUE_MAX = 32;

    /**
     * What one module's answer says, in three chips or a number.
     *
     * **Decided by the shape of the response and never by which module
     * produced it.** There is no roster mapping an object name to its
     * headline relation. One would read better — `AS15169 · US` — and
     * it is upkeep created in order to be deleted, because the
     * per-type visualisations that replace this are a later design and
     * the geolocation chips are exactly where a map slots in.
     *
     * Two modes:
     *
     * - **few** — the relations themselves, `name value`, deduplicated
     *   and capped, with a `+N` for what did not fit.
     * - **many** — the count and what was counted, `1,375 passive-dns`.
     *
     * **Every relation of a small object, not the first one.** *Show
     * the first attribute of each object* needs no roster and shows a
     * real value, so it occurs to everyone who reads this; it is wrong
     * on the first data it meets, because the `asn` object leads with
     * `last-seen` and the fact a reader came for is `asn`, two
     * relations later.
     *
     * **Deduplicated on the pair.** `mmdb_lookup` answers with one
     * object per database it consulted, so `country United States`
     * arrives three times, and three chips saying one thing would
     * spend the whole cap agreeing with themselves.
     *
     * Pure, like everything else here: the caller hands over a run as
     * the model shaped it — off the wire or out of the store, which
     * are the same shape — and gets back what to draw.
     *
     * @param array $run A shaped run
     * @return array `kind` is `chips`, `count` or `none`
     */
    public static function chipsFor(array $run)
    {
        $none = array(
            'kind' => 'none',
            'chips' => array(),
            'more' => 0,
            'count' => 0,
            'noun' => null,
        );
        if (!isset($run['state']) || $run['state'] !== 'ok') {
            return $none;
        }
        $total = isset($run['total']) ? (int)$run['total'] : 0;
        if ($total < 1) {
            return $none;
        }
        $chips = $total > self::CHIP_FEW
            ? array()
            : self::chipCandidates($run);
        /*
         * A small answer with nothing chippable in it falls back to
         * the count rather than to nothing. It happens: a module can
         * return one object whose every relation is a paragraph, and
         * *one geolocation* is a true summary where silence would
         * read as a module that had not run.
         */
        if (empty($chips)) {
            return array(
                'kind' => 'count',
                'chips' => array(),
                'more' => 0,
                'count' => $total,
                'noun' => self::chipNoun($run),
            );
        }
        return array(
            'kind' => 'chips',
            'chips' => array_slice($chips, 0, self::CHIP_CAP),
            'more' => max(0, count($chips) - self::CHIP_CAP),
            'count' => $total,
            'noun' => self::chipNoun($run),
        );
    }

    /**
     * What the module returned, named.
     *
     * The object name where there is one, because that is the word a
     * reader knows the answer by — `passive-dns` rather than
     * `results`. The commonest one where a module mixes them, and the
     * attribute type where a module returned no objects at all.
     *
     * @param array $run
     * @return string|null
     */
    private static function chipNoun(array $run)
    {
        $tally = self::chipTally(self::runList($run, 'objects'), 'name');
        if (empty($tally)) {
            $tally = self::chipTally(
                self::runList($run, 'attributes'),
                'type'
            );
        }
        if (empty($tally)) {
            $tally = self::chipTally(
                self::runList($run, 'elements'),
                'types'
            );
        }
        if (empty($tally)) {
            return null;
        }
        arsort($tally);
        return (string)key($tally);
    }

    /**
     * @param array $rows
     * @param string $key `types` is the list a simplified module sends
     * @return array name => count
     */
    private static function chipTally(array $rows, $key)
    {
        $tally = array();
        foreach ($rows as $row) {
            if ($key === 'types') {
                $types = isset($row['types']) ? (array)$row['types'] : array();
                $name = empty($types) ? '' : (string)reset($types);
            } else {
                $name = isset($row[$key]) ? (string)$row[$key] : '';
            }
            if ($name === '') {
                continue;
            }
            $tally[$name] = isset($tally[$name]) ? $tally[$name] + 1 : 1;
        }
        return $tally;
    }

    /**
     * Every `name value` pair the answer offers, in the order it
     * offered them, once each.
     *
     * A module returns one of three shapes and all three reduce to a
     * pair: an object's attributes carry an `object_relation`, a bare
     * attribute carries a `type`, and a `simplified` module's element
     * carries a list of types of which the first is the name. The
     * shape rule cannot tell them apart and does not need to.
     *
     * @param array $run
     * @return array
     */
    private static function chipCandidates(array $run)
    {
        $out = array();
        $seen = array();
        foreach (self::runList($run, 'objects') as $object) {
            $attributes = isset($object['attributes'])
                && is_array($object['attributes'])
                ? $object['attributes']
                : array();
            foreach ($attributes as $attribute) {
                $label = !empty($attribute['relation'])
                    ? $attribute['relation']
                    : (isset($attribute['type']) ? $attribute['type'] : '');
                self::chipAdd($out, $seen, $label, isset($attribute['value'])
                    ? $attribute['value'] : '');
            }
        }
        foreach (self::runList($run, 'attributes') as $attribute) {
            self::chipAdd(
                $out,
                $seen,
                isset($attribute['type']) ? $attribute['type'] : '',
                isset($attribute['value']) ? $attribute['value'] : ''
            );
        }
        foreach (self::runList($run, 'elements') as $element) {
            $types = isset($element['types'])
                ? (array)$element['types'] : array();
            self::chipAdd(
                $out,
                $seen,
                empty($types) ? '' : reset($types),
                isset($element['value']) ? $element['value'] : ''
            );
        }
        return $out;
    }

    /**
     * @param array $out
     * @param array $seen
     * @param string $label
     * @param string $value
     * @return void
     */
    private static function chipAdd(array &$out, array &$seen, $label,
        $value
    ) {
        $label = trim((string)$label);
        $value = trim((string)$value);
        if ($label === '' || $value === '') {
            return;
        }
        if (mb_strlen($value) > self::CHIP_VALUE_MAX) {
            return;
        }
        $key = $label . '|' . $value;
        if (isset($seen[$key])) {
            return;
        }
        $seen[$key] = true;
        $out[] = array('label' => $label, 'value' => $value);
    }

    /**
     * @param array $run
     * @param string $key
     * @return array
     */
    private static function runList(array $run, $key)
    {
        return isset($run[$key]) && is_array($run[$key])
            ? $run[$key]
            : array();
    }

    /**
     * Whether this profile marks anything `auto` for these types.
     *
     * The cheap half of *is there a panel to draw*. The page frame
     * asks it before it emits a container, and it has to answer
     * without the modules service, without the catalogue and without a
     * second profile read — which it can, because a declaration is a
     * document and the question is about the document alone.
     *
     * Looser than the panel's own test on purpose: a module declared
     * `auto` here may still turn out to be disabled, restricted or
     * filed under a type it does not accept, and every one of those is
     * a `GET /modules` away. Saying yes and then drawing nothing costs
     * an empty container; saying no would hide a panel that should
     * have been there.
     *
     * @param array $plan From `planFor`
     * @param array $types `typesFor` output
     * @return bool
     */
    public static function declaresAuto(array $plan, array $types)
    {
        if (empty($plan['in_force'])) {
            return false;
        }
        foreach ($types as $row) {
            $type = is_array($row) && isset($row['type'])
                ? $row['type']
                : $row;
            if (empty($plan['auto_run'][$type])) {
                continue;
            }
            foreach ($plan['auto_run'][$type] as $state) {
                if ($state === self::STATE_AUTO) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @param array $facts
     * @param string $key
     * @return array
     */
    private static function rows(array $facts, $key)
    {
        return isset($facts[$key]) && is_array($facts[$key])
            ? $facts[$key]
            : array();
    }

    /**
     * How much of what arrived ticked would leave the instance if the
     * reader pressed run.
     *
     * Used by the strip, and separate from `resolve()` because it is a
     * statement about the **selection** rather than about the
     * declaration: a selection that is entirely local has nothing to
     * warn about, and one carrying an external module is where the
     * tray's own "queries leave this instance" line is the whole
     * warning.
     *
     * @param array $resolved From resolve
     * @return int How many pre-selected modules leave the instance
     */
    public static function leavingCount(array $resolved)
    {
        $n = 0;
        foreach ($resolved['selected'] as $entry) {
            if ($entry['locality'] !== ModuleLocality::LOCAL) {
                $n++;
            }
        }
        return $n;
    }
}
