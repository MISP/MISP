<?php
/**
 * Loads the AttributeValue class for unit tests that run without the
 * framework. Not a test file.
 *
 * Required from setUp rather than at load time: by then PHPUnit has loaded
 * every test file, so an AppModel stub another file declares wins, and the
 * empty one below only applies when the test runs alone.
 */

if (!class_exists('AppModel', false)) {
    class AppModel
    {
    }
}

require_once __DIR__ . '/../Lib/Tools/ValueFieldTranslator.php';
require_once __DIR__ . '/../Lib/Tools/ValueConditionRewriter.php';
require_once __DIR__ . '/../Model/AttributeValue.php';
