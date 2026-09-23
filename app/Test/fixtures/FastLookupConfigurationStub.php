<?php
/** Loaded only inside isolated tests; never replaces other suites' Configure. */
if (!class_exists('Configure', false)) {
    class Configure
    {
        private static $values = [];
        public static function read($key) { return self::$values[$key] ?? null; }
        public static function write($key, $value) { self::$values[$key] = $value; }
    }
}
