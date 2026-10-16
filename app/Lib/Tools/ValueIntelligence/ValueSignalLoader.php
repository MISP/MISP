<?php

/**
 * The directory read that makes a signal available.
 *
 * Signal implementations are **discovered from the filesystem, not
 * registered in code**. An admin
 * drops a PHP file in `app/Lib/ValueSignals/` and it is picked up;
 * nothing anywhere holds a list of the shipped ones.
 *
 * MISP has built this loader twice and this follows both rather than
 * inventing a third shape. `Workflow` scans two roots — a shipped one
 * replaced on upgrade and a custom one never touched — memoises the
 * scan behind an initialised flag, and keeps loading failures in
 * `$error_while_loading` for the UI to show. `DecayingModel` builds its
 * formula catalogue out of a directory listing minus `Base.php`, which
 * is why the decay UI's formula dropdown is already a directory read.
 *
 * **One subject per pair of roots.** Two of them today — signals, and
 * the conflict rules that make a lean contested — each with its own
 * base class and its own two directories, and both inheriting every
 * rule below.
 *
 * The five rules a directory that executes its contents needs:
 *
 * 1. **Discovery is not activation.** This class says what
 *    exists; a profile's `signals` list says what runs. A copied file
 *    moves no score on the instance until someone edits a profile.
 * 2. **A colliding id is refused, not overridden.** Shipped
 *    files load first and keep their ids; a custom file naming one is
 *    logged and skipped. A silent override would mean two instances
 *    rendering the same ledger row from two different computations.
 * 3. **A broken file is an honest state, never a fatal.** It
 *    does not parse, the class is missing, the class is not a signal:
 *    logged, skipped, the id unavailable, and the reason kept for the
 *    editor.
 * 4. **One scan per request, and no cache across requests.**
 *    An admin who drops a file expects the next page load to see it,
 *    and a Redis-cached catalogue would mean waiting on a key they have
 *    never heard of.
 * 5. **Nothing in the UI ever writes one of these files.** No
 *    upload, no in-browser editor. Signals arrive by whatever mechanism
 *    the admin already uses to deploy code.
 */
class ValueSignalLoader
{
    const SUBJECT_SIGNAL = 'signal';

    const SUBJECT_ESCALATION = 'escalation';

    const SUBJECT_RENDERER = 'renderer';

    /**
     * Subjects, each a pair of roots and the base class its files must
     * extend. Paths are relative to `APP` and resolved at scan time,
     * because `APP` is not available while a class constant is parsed.
     *
     * Listed here rather than registered at boot because the two
     * shipped subjects are part of this class's own contract: a
     * `register()` call from elsewhere would have to happen before the
     * first lookup, and a lookup that silently found no directory
     * because a bootstrap line was missing is the one failure mode a
     * filesystem catalogue cannot report — an empty directory and an
     * unregistered subject look identical from here.
     *
     * @var array
     */
    private static $subjects = array(
        self::SUBJECT_SIGNAL => array(
            'shipped' => 'Model/ValueSignals/',
            'custom' => 'Lib/ValueSignals/',
            'base' => 'ValueSignalBase',
            'skip' => array('ValueSignalBase.php'),
        ),
        self::SUBJECT_ESCALATION => array(
            'shipped' => 'Model/ValueEscalations/',
            'custom' => 'Lib/ValueEscalations/',
            'base' => 'ValueEscalationBase',
            'skip' => array('ValueEscalationBase.php'),
        ),
        /*
         * The third subject, and the first with a second thing to keep
         * unique. A renderer is chosen by the object template its
         * answer carries, so two renderers claiming one template would
         * mean the same answer drawn differently depending on which
         * file the filesystem listed first — rule 2's failure mode
         * with the id check passing. `claims` names the property the
         * refusal also covers.
         */
        self::SUBJECT_RENDERER => array(
            'shipped' => 'Model/ValueRenderers/',
            'custom' => 'Lib/ValueRenderers/',
            'base' => 'ValueRendererBase',
            'skip' => array('ValueRendererBase.php'),
            'claims' => 'templates',
        ),
    );

    /** Memoised per process: subject => id => instance. */
    private static $loaded = array();

    /** Subject => filename => why it did not load. */
    private static $errors = array();

    /**
     * Register another subject — any future pair of roots that wants
     * the same five rules, and the seam a harness uses to point a
     * subject at a directory of its own.
     *
     * @param string $name
     * @param array $spec `shipped`, `custom`, `base`, `skip`
     * @return void
     */
    public static function register($name, array $spec)
    {
        self::$subjects[$name] = $spec;
        unset(self::$loaded[$name], self::$errors[$name]);
    }

    /**
     * Every implementation this instance has, keyed by id.
     *
     * @param string $subject
     * @return array id => instance
     */
    public static function classes($subject = self::SUBJECT_SIGNAL)
    {
        if (!isset(self::$loaded[$subject])) {
            self::$loaded[$subject] = self::scan($subject);
        }
        return self::$loaded[$subject];
    }

    /**
     * The same set as the editor's palette reads it: identity only, no
     * instances.
     *
     * @param string $subject
     * @return array id => config
     */
    public static function catalogue($subject = self::SUBJECT_SIGNAL)
    {
        $catalogue = array();
        foreach (self::classes($subject) as $id => $instance) {
            $catalogue[$id] = $instance->getConfig();
        }
        return $catalogue;
    }

    /**
     * One implementation, or null when this instance does not have it —
     * an honest state, which the engine renders in `not_counted`
     * rather than dropping the row.
     *
     * @param string $id
     * @param string $subject
     * @return object|null
     */
    public static function get($id, $subject = self::SUBJECT_SIGNAL)
    {
        $classes = self::classes($subject);
        return isset($classes[$id]) ? $classes[$id] : null;
    }

    /**
     * Why each file that failed to load failed, for the editor's page.
     *
     * Keyed by filename rather than by id, because a file that will not
     * parse has no id to be keyed by — which is exactly the case an
     * admin with a typo needs to see.
     *
     * @param string $subject
     * @return array filename => reason
     */
    public static function errors($subject = self::SUBJECT_SIGNAL)
    {
        self::classes($subject);
        return isset(self::$errors[$subject])
            ? self::$errors[$subject]
            : array();
    }

    /**
     * Drop the memoised scan.
     *
     * For the harnesses and for a long-running worker that has just had
     * a file dropped under it; a web request never needs it.
     *
     * @param string|null $subject Null forgets every subject
     * @return void
     */
    public static function forget($subject = null)
    {
        if ($subject === null) {
            self::$loaded = array();
            self::$errors = array();
            return;
        }
        unset(self::$loaded[$subject], self::$errors[$subject]);
    }

    /**
     * The scan itself: shipped root first, so rule 2's collision
     * refusal has something to refuse against.
     *
     * @param string $subject
     * @return array id => instance
     */
    private static function scan($subject)
    {
        self::$errors[$subject] = array();
        if (!isset(self::$subjects[$subject])) {
            return array();
        }
        $spec = self::$subjects[$subject];
        /*
         * The base class, before anything that extends it. `Workflow`
         * gets this from `App::uses('WorkflowBaseModule',
         * 'Model/WorkflowModules')` at the top of its model; this
         * requires the file instead, so the loader stays runnable with
         * no CakePHP booted — which is what lets the harness drive it
         * with no framework and no database. It lives in the shipped
         * root and is in `skip`, so the scan itself never sees it.
         */
        if (!class_exists($spec['base'], false)) {
            $base = APP . $spec['shipped'] . $spec['base'] . '.php';
            if (is_file($base)) {
                include_once $base;
            }
        }
        $loaded = array();
        /* What each accepted file took, where the subject names a
         * second uniqueness key: claim => the id holding it. */
        $claimed = array();
        foreach (array('shipped', 'custom') as $origin) {
            if (empty($spec[$origin])) {
                continue;
            }
            $root = APP . $spec[$origin];
            foreach (self::listFiles($root, $spec) as $path) {
                self::take($subject, $spec, $path, $origin, $loaded,
                    $claimed);
            }
        }
        return $loaded;
    }

    /**
     * The `.php` files in one root, or nothing at all when the root is
     * absent.
     *
     * `glob` rather than `Folder::find`, for two reasons that are the
     * same reason twice: a missing directory has to be silence rather
     * than a condition — a fresh install has no custom root, and an
     * admin who deleted it has said what they meant — and the loader
     * stays runnable outside a booted CakePHP, which is what lets the
     * harness drive it with no framework and no database.
     *
     * @param string $root
     * @param array $spec
     * @return array Absolute paths, sorted
     */
    private static function listFiles($root, array $spec)
    {
        $found = glob($root . '*.php');
        if (!is_array($found)) {
            return array();
        }
        $skip = isset($spec['skip']) ? $spec['skip'] : array();
        $files = array();
        foreach ($found as $path) {
            if (!in_array(basename($path), $skip, true)) {
                $files[] = $path;
            }
        }
        return $files;
    }

    /**
     * Load one file and either keep its instance or record why not.
     *
     * @param string $subject
     * @param array $spec
     * @param string $path
     * @param string $origin `shipped` or `custom`
     * @param array $loaded By reference — the set being built
     * @param array $claimed By reference — claim => the id holding it
     * @return void
     */
    private static function take($subject, array $spec, $path, $origin,
        array &$loaded, array &$claimed
    ) {
        $instance = self::instantiate($spec, $path);
        if (is_string($instance)) {
            self::fail($subject, $path, $instance);
            return;
        }
        $id = $instance->id;
        if ($id === null || $id === '' || $id === 'to-override') {
            self::fail(
                $subject,
                $path,
                __('The class declares no id.')
            );
            return;
        }
        if (isset($loaded[$id])) {
            /*
             * Rule 2. `Workflow` throws
             * `WorkflowDuplicatedModuleIDException` here; this logs and
             * skips, because a page that renders an assessment must not
             * be taken down by a file in a directory an admin can
             * write to — rule 3 outranks the precedent's.
             */
            self::fail(
                $subject,
                $path,
                sprintf(
                    __('`%s` is already defined; this file is ignored'
                        . ' and the existing implementation keeps the'
                        . ' id.'),
                    $id
                )
            );
            return;
        }
        /*
         * Rule 2 again, on whatever else the subject has to keep
         * unique. Refused whole rather than per claim: a renderer that
         * kept the two templates nobody else had wanted and lost the
         * third would draw some answers and not others, which is a
         * harder state to diagnose than a file that plainly did not
         * load.
         */
        if (!empty($spec['claims'])) {
            $taken = self::claimsOf($instance, $spec['claims']);
            foreach ($taken as $claim) {
                if (!isset($claimed[$claim])) {
                    continue;
                }
                self::fail(
                    $subject,
                    $path,
                    sprintf(
                        __('`%1$s` is already drawn by `%2$s`; this'
                            . ' file is ignored and the existing'
                            . ' implementation keeps it.'),
                        $claim,
                        $claimed[$claim]
                    )
                );
                return;
            }
            foreach ($taken as $claim) {
                $claimed[$claim] = $id;
            }
        }
        $instance->is_custom = ($origin === 'custom');
        $loaded[$id] = $instance;
    }

    /**
     * The values one instance claims under the subject's claim
     * property, as strings and without repeats.
     *
     * A property that is missing or is not a list claims nothing,
     * which is how a subject without a second key costs nothing here.
     *
     * @param object $instance
     * @param string $property
     * @return array
     */
    private static function claimsOf($instance, $property)
    {
        if (!isset($instance->$property)
            || !is_array($instance->$property)
        ) {
            return array();
        }
        $out = array();
        foreach ($instance->$property as $claim) {
            $claim = trim((string)$claim);
            if ($claim !== '' && !in_array($claim, $out, true)) {
                $out[] = $claim;
            }
        }
        return $out;
    }

    /**
     * Include a file and construct its class, following
     * `Workflow::__getClassFromModuleFile()` — including its return
     * convention, where a string is the failure and an object is the
     * success.
     *
     * @param array $spec
     * @param string $path
     * @return object|string
     */
    private static function instantiate(array $spec, $path)
    {
        $className = basename($path, '.php');
        try {
            if (!class_exists($className, false)
                && !include_once $path
            ) {
                return sprintf(
                    __('Could not include %s.'),
                    $path
                );
            }
            if (!class_exists($className, false)) {
                return sprintf(
                    __('%1$s defines no class named `%2$s`.'),
                    basename($path),
                    $className
                );
            }
            $reflection = new ReflectionClass($className);
            if ($reflection->isAbstract()) {
                return sprintf(
                    __('`%s` is abstract.'),
                    $className
                );
            }
            $instance = $reflection->newInstance();
        } catch (Throwable $e) {
            return sprintf(
                __('%1$s did not load: %2$s'),
                basename($path),
                $e->getMessage()
            );
        }
        $base = $spec['base'];
        if (!($instance instanceof $base)) {
            return sprintf(
                __('`%1$s` is not a %2$s.'),
                $className,
                $base
            );
        }
        if ($instance->checkLoading() !== $base::LOADED) {
            return sprintf(
                __('`%s` did not answer the loader.'),
                $className
            );
        }
        return $instance;
    }

    /**
     * Record a loading failure, and log it where an admin will find it.
     *
     * @param string $subject
     * @param string $path
     * @param string $reason
     * @return void
     */
    private static function fail($subject, $path, $reason)
    {
        self::$errors[$subject][basename($path)] = $reason;
        if (class_exists('CakeLog')) {
            CakeLog::write(
                'error',
                sprintf(
                    'ValueSignalLoader (%1$s): %2$s — %3$s',
                    $subject,
                    basename($path),
                    $reason
                )
            );
        }
    }
}
