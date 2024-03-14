<?php

declare(strict_types=1);

namespace App\Model\Table;

use Cake\Core\Configure;

class CorrelationsTable extends AppTable
{
    private const CACHE_NAME = 'misp:top_correlations',
        CACHE_AGE = 'misp:top_correlations_age';

    public $belongsTo = array(
        'Attribute' => [
            'className' => 'Attribute',
            'foreignKey' => 'attribute_id'
        ],
        'Event' => array(
            'className' => 'Event',
            'foreignKey' => 'event_id'
        ),
        'Object' => array(
            'className' => 'Object',
            'foreignKey' => 'object_id'
        ),
        'CorrelationValue' => [
            'className' => 'CorrelationValue',
            'foreignKey' => 'value_id'
        ]
    );

    public $validEngines = [
        'Default' => 'default_correlations',
        'NoAcl' => 'no_acl_correlations',
        'Legacy' => 'correlations'
    ];

    public $actsAs = array(
        'Containable'
    );

    /** @var array */
    private $exclusions;

    /** @var bool */
    private $advancedCorrelationEnabled;

    /** @var array */
    private $cidrListCache;

    private $containCache = [];

    /** @var OverCorrelatingValue */
    public $OverCorrelatingValue;

    // public function __construct($id = false, $table = null, $ds = null)
    public function initialize(array $config): void
    {
        $correlationEngine = $this->getCorrelationModelName();
        $deadlockAvoidance = Configure::read('MISP.deadlock_avoidance') ?: false;
        // load the currently used correlation engine
        $this->addBehavior($correlationEngine . 'Correlation', ['deadlockAvoidance' => $deadlockAvoidance]);
        // getTableName() needs to be implemented by the engine - this points us to the table to be used
        $this->setTable($this->getTableName());
        $this->advancedCorrelationEnabled = (bool)Configure::read('MISP.enable_advanced_correlations');
        // load the overcorrelatingvalue model for chaining
        $this->OverCorrelatingValue = $this->fetchTable('OverCorrelatingValues');
    }

    /**
     * @param array $user User array
     * @param int $eventId Event ID
     * @param array $sgids List of sharing group IDs
     * @return array
     */
    public function getRelatedEventIds(array $user, int $eventId, array $sgids)
    {
        $relatedEventIds = $this->fetchRelatedEventIds($this, $user, $eventId, $sgids);
        if (empty($relatedEventIds)) {
            return [];
        }
        return $relatedEventIds;
    }

    /**
     * @return string
     */
    private function getCorrelationModelName()
    {
        return Configure::read('MISP.correlation_engine') ?: 'Default';
    }
}
