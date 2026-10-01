<?php
/**
 * GalaxyCluster::fetchGalaxyClusters() relation-fetch regression test.
 *
 * The $full branch used to run one GalaxyClusterRelation find() per cluster,
 * keyed on GalaxyCluster.id - a value that is unique per row, so the lookup
 * table it built never answered for a second cluster. This pins the batched
 * behaviour: one relation query for the whole result set, every cluster still
 * getting exactly its own relations, and an empty array when it has none.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB - the convention used by the other
 * tests under app/Test/ (see CollectionPullTest / DashboardCsvExportTest). The
 * framework stubs are class_exists guarded so a full-suite run shares whichever
 * file loaded them first, and the testable subclass bypasses the model
 * constructor and overrides find()/unbindModel(), so it does not depend on what
 * the shared AppModel stub happens to provide.
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Vendor/autoload.php';

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package = null)
        {
        }
    }
}

// The real Hash: fetchGalaxyClusters() collects the relation tag ids with
// Hash::extract() and a stand-in would only re-implement it.
if (!class_exists('Hash', false)) {
    require_once __DIR__ . '/../Lib/cakephp/lib/Cake/Utility/Hash.php';
}

// Verbatim copies of the CollectionCaptureTest/CollectionPullTest stubs so a
// full-suite run shares one contract whichever file loads them first. The
// CollectionTestFakeModel fallback is never reached here - both models are
// registered before fetchGalaxyClusters() is called.
if (!class_exists('ClassRegistry', false)) {
    class ClassRegistry
    {
        public static $instances = array();

        public static function init($name)
        {
            if (!isset(self::$instances[$name])) {
                self::$instances[$name] = new CollectionTestFakeModel();
            }
            return self::$instances[$name];
        }

        public static function reset()
        {
            self::$instances = array();
        }
    }
}

if (!class_exists('AppModel', false)) {
    class AppModel
    {
        public $alias = 'Collection';
        public $id = false;
        public $data = array();
        public $validationErrors = array();

        public function create($data = array())
        {
            $this->id = false;
        }

        public function save($data = null, $validate = true, $fieldList = array())
        {
            return true;
        }

        public function find($type, $options = array())
        {
            return array();
        }
    }
}

require_once __DIR__ . '/../Model/GalaxyCluster.php';

/**
 * GalaxyClusterRelation stand-in. Records the conditions of every find() and
 * answers from a fixed set of rows, matching galaxy_cluster_id whether it
 * arrives as a single id or as a list.
 */
class GalaxyClusterFetchRelationModel
{
    public $rows = array();
    public $findConditions = array();
    public $GalaxyClusterRelationTag;

    public function __construct()
    {
        $this->GalaxyClusterRelationTag = new GalaxyClusterFetchRelationTagModel();
    }

    public function buildConditions($user, $clusterConditions = true, $alias = false)
    {
        return array();
    }

    public function find($type, $params = array())
    {
        $condition = $params['conditions']['GalaxyClusterRelation.galaxy_cluster_id'];
        $this->findConditions[] = $condition;
        $matches = array();
        foreach ($this->rows as $row) {
            if (in_array($row['GalaxyClusterRelation']['galaxy_cluster_id'], (array)$condition)) {
                $matches[] = $row;
            }
        }
        return $matches;
    }
}

class GalaxyClusterFetchRelationTagModel
{
    public $Tag;

    public function __construct()
    {
        $this->Tag = new GalaxyClusterFetchTagModel();
    }
}

class GalaxyClusterFetchTagModel
{
    public function find($type, $params = array())
    {
        return array();
    }
}

class GalaxyClusterFetchTargetingModel
{
    public function fetchRelations($user, $options, $full = false, $renameField = 'SourceCluster')
    {
        return array();
    }
}

class GalaxyClusterFetchEventModel
{
    public function __cacheSharingGroupData($user, $useCache = false)
    {
        return array();
    }
}

/**
 * GalaxyCluster with the database removed: the constructor (which reads the
 * schema) is bypassed, find() returns the injected clusters and the associated
 * models are the stand-ins above.
 */
class GalaxyClusterFetchTestable extends GalaxyCluster
{
    public $alias = 'GalaxyCluster';
    public $clusters = array();
    public $GalaxyClusterRelation;
    public $TargetingClusterRelation;
    public $Event;

    public function __construct($id = false, $table = null, $ds = null)
    {
        // Deliberately does not call parent::__construct (schema lookup).
    }

    public function find($type, $params = array())
    {
        return $this->clusters;
    }

    public function unbindModel($params, $reset = true)
    {
        return true;
    }
}

class GalaxyClusterFetchTest extends TestCase
{
    public function setUp(): void
    {
        ClassRegistry::reset();
    }

    public function testRelationsAreFetchedInOneQueryForAllClusters()
    {
        $relationModel = $this->relationModel();
        $this->fetch($relationModel);
        $this->assertCount(1, $relationModel->findConditions);
        $this->assertSame(array(1, 2, 3), $relationModel->findConditions[0]);
    }

    public function testEveryClusterKeepsItsOwnRelations()
    {
        $clusters = $this->fetch($this->relationModel());
        $this->assertSame(
            array(10, 11),
            array_column($clusters[0]['GalaxyCluster']['GalaxyClusterRelation'], 'id')
        );
        $this->assertSame(array(), $clusters[1]['GalaxyCluster']['GalaxyClusterRelation']);
        $this->assertSame(
            array(12),
            array_column($clusters[2]['GalaxyCluster']['GalaxyClusterRelation'], 'id')
        );
    }

    public function testRelationFieldsAreFlattenedIntoTheRelationRow()
    {
        $clusters = $this->fetch($this->relationModel());
        $relation = $clusters[0]['GalaxyCluster']['GalaxyClusterRelation'][0];
        $this->assertArrayNotHasKey('GalaxyClusterRelation', $relation);
        $this->assertSame(1, $relation['galaxy_cluster_id']);
        $this->assertSame(array('id' => 1), $relation['SourceCluster']);
    }

    private function relationModel()
    {
        $relationModel = new GalaxyClusterFetchRelationModel();
        $relationModel->rows = array(
            $this->relation(10, 1),
            $this->relation(11, 1),
            $this->relation(12, 3),
        );
        return $relationModel;
    }

    private function relation($id, $clusterId)
    {
        return array(
            'GalaxyClusterRelation' => array(
                'id' => $id,
                'galaxy_cluster_id' => $clusterId,
                'referenced_galaxy_cluster_id' => 99,
                'distribution' => 3,
                'sharing_group_id' => 0,
            ),
            'SharingGroup' => array(),
            'SourceCluster' => array('id' => $clusterId),
            'GalaxyClusterRelationTag' => array(),
        );
    }

    private function fetch(GalaxyClusterFetchRelationModel $relationModel)
    {
        ClassRegistry::$instances['GalaxyClusterRelation'] = $relationModel;
        ClassRegistry::$instances['Event'] = new GalaxyClusterFetchEventModel();
        $galaxyCluster = new GalaxyClusterFetchTestable();
        $galaxyCluster->GalaxyClusterRelation = $relationModel;
        $galaxyCluster->TargetingClusterRelation = new GalaxyClusterFetchTargetingModel();
        $galaxyCluster->clusters = array(
            array('GalaxyCluster' => array('id' => 1, 'sharing_group_id' => 0)),
            array('GalaxyCluster' => array('id' => 2, 'sharing_group_id' => 0)),
            array('GalaxyCluster' => array('id' => 3, 'sharing_group_id' => 0)),
        );
        $user = array('org_id' => 1, 'Role' => array('perm_site_admin' => 1));
        return $galaxyCluster->fetchGalaxyClusters($user, array(), true);
    }
}
