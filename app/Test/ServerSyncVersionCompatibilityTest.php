<?php
require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}

require_once __DIR__ . '/../Lib/Tools/ServerSyncTool.php';

class VersionedServerSync extends ServerSyncTool
{
    private $version;

    public function __construct($version)
    {
        $this->version = $version;
    }

    public function info()
    {
        return ['version' => $this->version];
    }
}

class ServerSyncVersionCompatibilityTest extends TestCase
{
    public function testCrossMajorCompatiblePairs()
    {
        $this->assertTrue(ServerSyncTool::isCrossMajorCompatible('2.5.50', '3.0.0'));
        $this->assertTrue(ServerSyncTool::isCrossMajorCompatible('3.0.0', '2.5.50'));
        $this->assertTrue(ServerSyncTool::isCrossMajorCompatible('3.1.2', '2.5.0'));
    }

    public function testCrossMajorIncompatiblePairs()
    {
        $this->assertFalse(ServerSyncTool::isCrossMajorCompatible('2.4.200', '3.0.0'));
        $this->assertFalse(ServerSyncTool::isCrossMajorCompatible('3.0.0', '2.4.200'));
        $this->assertFalse(ServerSyncTool::isCrossMajorCompatible('2.5.50', '2.5.49'));
        $this->assertFalse(ServerSyncTool::isCrossMajorCompatible('3.0.0', '3.0.1'));
        $this->assertFalse(ServerSyncTool::isCrossMajorCompatible('2.5.50', '4.0.0'));
    }

    public function featureProvider()
    {
        return [
            [ServerSyncTool::FEATURE_ORG_RULE, '2.4.123', '2.4.124'],
            [ServerSyncTool::FEATURE_PROPOSALS, '2.4.110', '2.4.111'],
            [ServerSyncTool::FEATURE_POST_TEST, '2.4.68', '2.4.69'],
            [ServerSyncTool::FEATURE_PROTECTED_EVENT, '2.4.155', '2.4.156'],
            [ServerSyncTool::FEATURE_SIGHTING_REST_SEARCH, '2.4.164', '2.4.165'],
        ];
    }

    /**
     * @dataProvider featureProvider
     */
    public function testVersionGatedFeatures($feature, $lastWithout, $firstWith)
    {
        $this->assertFalse((new VersionedServerSync($lastWithout))->isSupported($feature));
        $this->assertTrue((new VersionedServerSync($firstWith))->isSupported($feature));
        $this->assertTrue((new VersionedServerSync('2.5.0'))->isSupported($feature));
        $this->assertTrue((new VersionedServerSync('3.0.0'))->isSupported($feature));
    }

    public function testValueTargetsNeedThreeZero()
    {
        foreach (['2.4.200', '2.5.0', '2.5.50'] as $version) {
            $this->assertFalse((new VersionedServerSync($version))->isSupported(ServerSyncTool::FEATURE_VALUE_TARGETS), $version);
        }
        foreach (['3.0.0', '3.1.2'] as $version) {
            $this->assertTrue((new VersionedServerSync($version))->isSupported(ServerSyncTool::FEATURE_VALUE_TARGETS), $version);
        }
    }
}
