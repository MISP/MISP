<?php
App::uses('EventTemplateDependencyMissingException', 'Tools');

/**
 * Runtime check for the composer packages required by the event-templating
 * feature.
 *
 * MISP's standard upgrade flow (git pull + `cake Admin runUpdates`) does NOT
 * run `composer install`. Operators must do that manually after upgrading.
 * Until they do, event-templating controllers and libs should surface a
 * clear admin-instruction message rather than throwing raw type errors
 * from "class not found" at the first use site.
 *
 * Usage:
 *   - Controllers call `EventTemplateDependencies::missing()` in their
 *     beforeFilter and render a friendly error page when it's non-empty.
 *   - Libs that require a specific package call `requireAll()` or
 *     `require(['pkg/name'])` at first use and let the exception propagate
 *     to the caller, which is expected to catch and render it.
 *
 * See docs/dev/event-templating-prd.md §11.2.
 */
class EventTemplateDependencies
{
    /**
     * Map of composer package name => a canonical class the package provides.
     * `class_exists` is used as the liveness check because it is cheap and
     * does not rely on composer metadata being present on disk.
     *
     * @var array<string,string>
     */
    private static $deps = array(
        'league/commonmark'          => 'League\\CommonMark\\CommonMarkConverter',
        'justinrainbow/json-schema'  => 'JsonSchema\\Validator',
    );

    /**
     * Returns the list of composer package names the event-templating feature
     * needs but that are not loadable in this PHP runtime. Empty array means
     * every dep is present.
     *
     * @return string[]
     */
    public static function missing()
    {
        $missing = array();
        foreach (self::$deps as $package => $canonicalClass) {
            if (!class_exists($canonicalClass)) {
                $missing[] = $package;
            }
        }
        return $missing;
    }

    /**
     * Throws EventTemplateDependencyMissingException if any dep is missing.
     */
    public static function requireAll()
    {
        $missing = self::missing();
        if (!empty($missing)) {
            throw new EventTemplateDependencyMissingException($missing);
        }
    }

    /**
     * Throws EventTemplateDependencyMissingException if any of the given
     * package names is not installed. Useful for libs that depend on just
     * one of the deps (e.g. the Markdown renderer only needs commonmark).
     *
     * Unknown package names raise InvalidArgumentException — passing a
     * typoed name is a coding bug and should fail loud rather than be
     * silently treated as satisfied.
     *
     * @param string[] $packages
     */
    public static function requireSome(array $packages)
    {
        $missing = array();
        foreach ($packages as $package) {
            if (!isset(self::$deps[$package])) {
                throw new InvalidArgumentException(sprintf(
                    'Unknown event-templating dependency "%s". Known deps: %s.',
                    $package,
                    implode(', ', array_keys(self::$deps))
                ));
            }
            if (!class_exists(self::$deps[$package])) {
                $missing[] = $package;
            }
        }
        if (!empty($missing)) {
            throw new EventTemplateDependencyMissingException($missing);
        }
    }
}
