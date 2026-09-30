<?php
// Real Cake models/datasource; omit unrelated notifications, workflows and files.
$cake = getenv('MISP_FASTLOOKUP_CAKE_DIR') ?: dirname(__DIR__, 2) . '/Lib/cakephp/lib/Cake';
define('DS', DIRECTORY_SEPARATOR);
define('CAKE', rtrim($cake, '/') . '/');
define('ROOT', dirname(__DIR__, 3));
define('APP', ROOT . '/app/');
define('APP_DIR', 'app');
define('APPLIBS', APP . 'Lib/');
define('CORE_PATH', dirname(rtrim(CAKE, '/')) . '/');
define('CAKE_CORE_INCLUDE_PATH', dirname(rtrim(CAKE, '/')));
define('TMP', sys_get_temp_dir() . '/');
define('CACHE', TMP);
define('CONFIG', TMP . 'fastlookup-deletion-' . bin2hex(random_bytes(8)) . '/');
mkdir(CONFIG);
file_put_contents(CONFIG . 'database.php', '<?php class DATABASE_CONFIG {}');
register_shutdown_function(function () {
    unlink(CONFIG . 'database.php');
    rmdir(CONFIG);
});
require CAKE . 'basics.php';
require CAKE . 'Core/App.php';
require CAKE . 'Error/exceptions.php';
spl_autoload_register(['App', 'load']);
App::uses('Configure', 'Core');
App::uses('Cache', 'Cache');
App::uses('CakeObject', 'Core');
App::uses('ConnectionManager', 'Model');
App::build(['Model' => [APP . 'Model/'], 'Tools' => [APPLIBS . 'Tools/'],
    'Model/Datasource/Database' => [APP . 'Model/Datasource/Database/'],
    'Migration' => [APPLIBS . 'Migration/']], App::PREPEND);
App::uses('Event', 'Model');
App::uses('MispAttribute', 'Model');
App::uses('ShadowAttribute', 'Model');
App::uses('EventReport', 'Model');
App::uses('EventReportTag', 'Model');
App::uses('AttachmentScan', 'Model');
App::uses('FuzzyCorrelateSsdeep', 'Model');
App::uses('FastLookupIndexManager', 'Tools');
Configure::write('Cache.disable', true);
Configure::write('debug', 2);
error_reporting(E_ALL & ~E_DEPRECATED);
Configure::write('MISP.completely_disable_correlation', true);

trait FastLookupDeletionBareModel
{
    protected function _mergeVars($properties, $class, $normalize = true)
    {
        parent::_mergeVars(array_values(array_diff($properties, ['actsAs', 'belongsTo', 'hasMany'])), $class, $normalize);
    }
}

trait FastLookupDeletionFixture
{
    use FastLookupDeletionBareModel;

    public $nestedSave = false;
    public $veto = false;

    public function beforeDelete($cascade = true)
    {
        if ($this->nestedSave) {
            $audit = new Model(['name' => 'DeletionAudit', 'table' => 'deletion_audit', 'ds' => 'default']);
            $audit->save(['event_id' => 1]);
        }
        if ($this->alias === 'Attribute') {
            $this->data['Attribute'] = ['event_id' => 1, 'deleted' => true];
        }
        return !$this->veto;
    }
}

class FastLookupDeletionEvent extends Event
{
    use FastLookupDeletionFixture;
    public $actsAs = [];
    public $belongsTo = [];
    public $hasMany = [];
    public $alias = 'Event';

    public function __construct()
    {
        Model::__construct(false, 'events', 'default');
        // Models quickDelete() reads or purges before its raw per-table deletes.
        $this->Attribute = new FastLookupDeletionAttribute();
        ClassRegistry::addObject('MispAttribute', $this->Attribute);
        $this->ShadowAttribute = new FastLookupDeletionShadowAttribute();
        $this->EventReport = new FastLookupDeletionEventReport();
        new FastLookupDeletionAttachmentScan();
        new FastLookupDeletionFuzzyCorrelateSsdeep();
    }
}

class FastLookupDeletionShadowAttribute extends ShadowAttribute
{
    use FastLookupDeletionBareModel;
    public $actsAs = [];
    public $belongsTo = [];
    public $hasMany = [];

    public function __construct()
    {
        AppModel::__construct(false, 'shadow_attributes', 'default');
    }
}

class FastLookupDeletionEventReport extends EventReport
{
    use FastLookupDeletionBareModel;
    public $name = 'EventReport';
    public $actsAs = [];
    public $belongsTo = [];
    public $hasMany = [];

    public function __construct()
    {
        AppModel::__construct(false, 'event_reports', 'default');
        $this->EventReportTag = new FastLookupDeletionEventReportTag();
    }
}

class FastLookupDeletionEventReportTag extends EventReportTag
{
    use FastLookupDeletionBareModel;
    public $name = 'EventReportTag';
    public $actsAs = [];
    public $belongsTo = [];
    public $hasMany = [];

    public function __construct()
    {
        AppModel::__construct(false, 'event_report_tags', 'default');
    }
}

class FastLookupDeletionAttachmentScan extends AttachmentScan
{
    use FastLookupDeletionBareModel;
    public $name = 'AttachmentScan';
    public $actsAs = [];
    public $belongsTo = [];
    public $hasMany = [];

    public function __construct()
    {
        AppModel::__construct(false, 'attachment_scans', 'default');
    }
}

class FastLookupDeletionFuzzyCorrelateSsdeep extends FuzzyCorrelateSsdeep
{
    use FastLookupDeletionBareModel;
    public $name = 'FuzzyCorrelateSsdeep';
    public $actsAs = [];
    public $belongsTo = [];
    public $hasMany = [];

    public function __construct()
    {
        AppModel::__construct(false, 'fuzzy_correlate_ssdeep', 'default');
    }
}

class FastLookupDeletionAttribute extends MispAttribute
{
    use FastLookupDeletionFixture;
    public $actsAs = [];
    public $belongsTo = [];
    public $hasMany = [];

    public function __construct()
    {
        AppModel::__construct(false, 'attributes', 'default');
    }
}

/** Runs MispAttribute's own delete callbacks; only external services are stubbed. */
class FastLookupRealCallbackAttribute extends MispAttribute
{
    public $actsAs = [];
    public $belongsTo = [];
    public $hasMany = [];

    protected function _mergeVars($properties, $class, $normalize = true)
    {
        parent::_mergeVars(array_values(array_diff($properties, ['actsAs', 'belongsTo', 'hasMany'])), $class, $normalize);
    }

    public function __construct()
    {
        Model::__construct(false, 'attributes', 'default');
        $this->Event = new FastLookupDeletionEvent();
        $this->Correlation = new class {
            public function beforeSaveCorrelation($attribute) {}
        };
    }
}
