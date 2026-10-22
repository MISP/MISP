<?php
/**
 * Which relations GalaxyCluster::generateMissingRelations() re-points: a
 * relation's cached target id is 0, the id of a deleted row (a galaxy update
 * replaced the cluster), or a cluster carrying another UUID. Pure PHPUnit: the
 * framework classes GalaxyCluster.php needs at load time are stubbed.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}

if (!class_exists('AppModel', false)) {
    class AppModel
    {
    }
}

require_once __DIR__ . '/../Model/GalaxyCluster.php';

class GalaxyRelationTargetRepairTest extends \PHPUnit\Framework\TestCase
{
    private function relation($uuid, $id)
    {
        return ['referenced_galaxy_cluster_uuid' => $uuid, 'referenced_galaxy_cluster_id' => $id];
    }

    public function testADeletedTargetIsRepointedToTheClusterCarryingItsUuid()
    {
        $repairs = GalaxyCluster::relationTargetRepairs(
            [$this->relation('t1566', 13651), $this->relation('t1566', 9386)],
            ['t1566' => 47241]
        );
        $this->assertSame(['t1566' => ['to' => 47241, 'from' => [13651, 9386]]], $repairs);
    }

    public function testAMissingTargetIsFilledInAndAnUnknownUuidIsLeftAlone()
    {
        $repairs = GalaxyCluster::relationTargetRepairs(
            [$this->relation('apt29', 0), $this->relation('nowhere', 0)],
            ['apt29' => 72581]
        );
        $this->assertSame(['apt29' => ['to' => 72581, 'from' => [0]]], $repairs);
    }

    public function testADeletedTargetNoClusterCarriesAnyMoreIsCleared()
    {
        $repairs = GalaxyCluster::relationTargetRepairs([$this->relation('gone', 512)], []);
        $this->assertSame(['gone' => ['to' => 0, 'from' => [512]]], $repairs);
    }
}
