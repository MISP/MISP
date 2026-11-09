<?php
/** Exercise the same source audit as PyMISP's live remote_acl() test. */
require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!defined('DS')) {
    define('DS', DIRECTORY_SEPARATOR);
}
if (!defined('APP')) {
    define('APP', __DIR__ . '/../');
}
if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class = null, $package = null) {}
    }
}
if (!class_exists('Component', false)) {
    class Component {}
}

require_once __DIR__ . '/../Lib/cakephp/lib/Cake/Utility/Folder.php';
require_once __DIR__ . '/../Lib/Tools/FileAccessTool.php';
require_once __DIR__ . '/../Controller/Component/ACLComponent.php';

class ACLControllerActionsTest extends TestCase
{
    public function testControllerActionsHaveAclEntries()
    {
        $acl = (new ReflectionClass(ACLComponent::class))->newInstanceWithoutConstructor();
        $this->assertSame([], $acl->findMissingFunctionNames());
    }
}
