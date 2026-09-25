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
App::uses('FastLookupIndexManager', 'Tools');
Configure::write('Cache.disable', true);
Configure::write('debug', 2);
error_reporting(E_ALL & ~E_DEPRECATED);
Configure::write('MISP.completely_disable_correlation', true);

trait FastLookupDeletionFixture
{
    public $nestedSave = false;
    public $veto = false;

    protected function _mergeVars($properties, $class, $normalize = true)
    {
        parent::_mergeVars(array_values(array_diff($properties, ['actsAs', 'belongsTo', 'hasMany'])), $class, $normalize);
    }

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
        Model::__construct(false, 'attributes', 'default');
    }
}
