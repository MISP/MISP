<?php
App::uses('AuditLog', 'Model');

class AuditLogBehavior extends ModelBehavior
{
    /** @var array */
    private $config;

    /** @var array|null */
    private $old;

    /** @var AuditLog|null */
    private $AuditLog;

    /** @var bool */
    private $enabled;

    private $skipFields = [
        'id' => true,
        'lastpushedid' => true,
        'timestamp' => true,
        'revision' => true,
        'modified' => true,
        'date_modified' => true, // User
        'current_login' => true, // User
        'last_login' => true, // User
        'newsread' => true, // User
        'proposal_email_lock' => true, // Event
        'warninglist_entry_count' => true, // Warninglist
    ];

    private $modelInfo = [
        'Event' => 'info',
        'User' => 'email',
        'Object' => 'name',
        'EventReport' => 'name',
        'Server' => 'name',
        'Feed' => 'name',
        'Role' => 'name',
        'SharingGroup' => 'name',
        'Tag' => 'name',
        'TagCollection' => 'name',
        'Taxonomy' => 'namespace',
        'Organisation' => 'name',
        'AdminSetting' => 'setting',
        'UserSetting' => 'setting',
        'Galaxy' => 'name',
        'GalaxyCluster' => 'value',
        'Warninglist' => 'name',
    ];

    public function __construct()
    {
        parent::__construct();
        $this->enabled = Configure::read('MISP.log_new_audit');
    }

    public function setup(Model $model, $config = [])
    {
        $this->config = $config;
        // Generate model info for attribute and proposals
        $attributeInfo = function (array $new, array $old) {
            $category = isset($new['category']) ? $new['category'] : $old['category'];
            $type = isset($new['type']) ? $new['type'] : $old['type'];
            $value1 = trim(isset($new['value1']) ? $new['value1'] : $old['value1']);
            $value2 = trim(isset($new['value2']) ? $new['value2'] : $old['value2']);
            $value = $value1 . (empty($value2) ? '' : '|' . $value2);
            return "$category/$type $value";
        };
        $this->modelInfo['Attribute'] = $attributeInfo;
        $this->modelInfo['ShadowAttribute'] = $attributeInfo;
        $this->modelInfo['AuthKey'] = function (array $new, array $old) {
            $start = isset($new['authkey_start']) ? $new['authkey_start'] : $old['authkey_start'];
            $end = isset($new['authkey_end']) ? $new['authkey_end'] : $old['authkey_end'];
            return "$start********************************$end";
        };
    }

    public function beforeSave(Model $model, $options = [])
    {
        if (!$this->enabled) {
            return true;
        }
        if ($model->id) {
            $this->old = $model->find('first', [
                'conditions' => [$model->alias . '.' . $model->primaryKey => $model->id],
                'recursive' => -1,
                'callbacks' => false,
            ]);
        } else {
            $this->old = null;
        }
        return true;
    }

    public function afterSave(Model $model, $created, $options = [])
    {
        if (!$this->enabled) {
            return;
        }

        if ($model->id) {
            $id = $model->id;
        } else if ($model->insertId) {
            $id = $model->insertId;
        } else {
            $id = null;
        }

        if ($created) {
            $action = AuditLog::ACTION_ADD;
        } else {
            $action = AuditLog::ACTION_EDIT;
            if (isset($model->data[$model->alias]['deleted'])) {
                if ($model->data[$model->alias]['deleted']) {
                    $action = AuditLog::ACTION_SOFT_DELETE;
                } else if (!$model->data[$model->alias]['deleted'] && $this->old[$model->alias]['deleted']) {
                    $action = AuditLog::ACTION_UNDELETE;
                }
            }
        }

        $changedFields = $this->changedFields($model, isset($options['fieldList']) ? $options['fieldList'] : null);
        if (empty($changedFields)) {
            return;
        }

        if ($model->name === 'Event') {
            $eventId = $id;
        } else if (isset($model->data[$model->alias]['event_id'])) {
            $eventId = $model->data[$model->alias]['event_id'];
        } else if (isset($this->old[$model->alias]['event_id'])) {
            $eventId = $this->old[$model->alias]['event_id'];
        } else {
            $eventId = null;
        }

        $modelTitle = null;
        if (isset($this->modelInfo[$model->name])) {
            $modelTitleField = $this->modelInfo[$model->name];
            if (is_callable($modelTitleField)) {
                $modelTitle = $modelTitleField($model->data[$model->alias], isset($this->old[$model->alias]) ? $this->old[$model->alias] : []);
            } else if (isset($model->data[$model->alias][$modelTitleField])) {
                $modelTitle = $model->data[$model->alias][$modelTitleField];
            } else if ($this->old[$model->alias][$modelTitleField]) {
                $modelTitle = $this->old[$model->alias][$modelTitleField];
            }
        }

        $modelName = $model->name === 'MispObject' ? 'Object' : $model->name;

        if ($modelName === 'AttributeTag' || $modelName === 'EventTag') {
            $action = $model->data[$model->alias]['local'] ? AuditLog::ACTION_TAG_LOCAL : AuditLog::ACTION_TAG;
            $tagInfo = $this->getTagInfo($model, $model->data[$model->alias]['tag_id']);
            if ($tagInfo) {
                $modelTitle = $tagInfo['tag_name'];
                if ($tagInfo['is_galaxy']) {
                    $action = $model->data[$model->alias]['local'] ? AuditLog::ACTION_GALAXY_LOCAL : AuditLog::ACTION_GALAXY;
                    if ($tagInfo['galaxy_cluster_name']) {
                        $modelTitle = $tagInfo['galaxy_cluster_name'];
                    }
                }
            }
            $id = $modelName === 'AttributeTag' ? $model->data[$model->alias]['attribute_id'] : $model->data[$model->alias]['event_id'];
            $modelName = $modelName === 'AttributeTag' ? 'Attribute' : 'Event';
        }

        if ($modelName === 'Event') {
            if (isset($changedFields['published'][1]) && $changedFields['published'][1]) {
                $action = AuditLog::ACTION_PUBLISH;
            } else if (isset($changedFields['sighting_timestamp'][1]) && $changedFields['sighting_timestamp'][1]) {
                $action = AuditLog::ACTION_PUBLISH_SIGHTINGS;
            }
        }

        $this->auditLog()->insert([
            'action' => $action,
            'model' => $modelName,
            'model_id' => $id,
            'model_title' => $modelTitle,
            'event_id' => $eventId,
            'change' => $changedFields,
        ]);
    }

    public function beforeDelete(Model $model, $cascade = true)
    {
        if (!$this->enabled) {
            return true;
        }
        $model->recursive = -1;
        $model->read();
        return true;
    }

    public function afterDelete(Model $model)
    {
        if (!$this->enabled) {
            return;
        }
        if ($model->name === 'Event') {
            $eventId = $model->id;
        } else {
            $eventId = isset($model->data[$model->alias]['event_id']) ? $model->data[$model->alias]['event_id'] : null;
        }

        $modelTitle = null;
        if (isset($this->modelInfo[$model->name])) {
            $modelTitleField = $this->modelInfo[$model->name];
            if (is_callable($modelTitleField)) {
                $modelTitle = $modelTitleField($model->data[$model->alias], []);
            } else if (isset($model->data[$model->alias][$modelTitleField])) {
                $modelTitle = $model->data[$model->alias][$modelTitleField];
            }
        }

        $modelName = $model->name === 'MispObject' ? 'Object' : $model->name;
        $action = AuditLog::ACTION_DELETE;
        $id = $model->id;

        if ($modelName === 'AttributeTag' || $modelName === 'EventTag') {
            $action = $model->data[$model->alias]['local'] ? AuditLog::ACTION_REMOVE_TAG_LOCAL : AuditLog::ACTION_REMOVE_TAG;
            $tagInfo = $this->getTagInfo($model, $model->data[$model->alias]['tag_id']);
            if ($tagInfo) {
                $modelTitle = $tagInfo['tag_name'];
                if ($tagInfo['is_galaxy']) {
                    $action = $model->data[$model->alias]['local'] ? AuditLog::ACTION_REMOVE_GALAXY_LOCAL : AuditLog::ACTION_REMOVE_GALAXY;
                    if ($tagInfo['galaxy_cluster_name']) {
                        $modelTitle = $tagInfo['galaxy_cluster_name'];
                    }
                }
            }
            $id = $modelName === 'AttributeTag' ? $model->data[$model->alias]['attribute_id'] : $model->data[$model->alias]['event_id'];
            $modelName = $modelName === 'AttributeTag' ? 'Attribute' : 'Event';
        }

        $this->auditLog()->insert([
            'action' => $action,
            'model' => $modelName,
            'model_id' => $id,
            'model_title' => $modelTitle,
            'event_id' => $eventId,
            'change' => $this->changedFields($model),
        ]);
    }

    /**
     * @param Model $model
     * @param int $tagId
     * @return array|null
     */
    private function getTagInfo(Model $model, $tagId)
    {
        $tag = $model->Tag->find('first', [
            'conditions' => ['Tag.id' => $tagId],
            'recursive' => -1,
            'fields' => ['Tag.name', 'Tag.is_galaxy'],
        ]);
        if (empty($tag)) {
            return null;
        }

        $galaxyClusterName = null;
        if ($tag['Tag']['is_galaxy']) {
            if (!isset($this->GalaxyCluster)) {
                $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
            }
            $galaxyCluster = $this->GalaxyCluster->find('first', [
                'conditions' => ['GalaxyCluster.tag_name' => $tag['Tag']['name']],
                'recursive' => -1,
                'fields' => ['GalaxyCluster.value'],
            ]);
            if (!empty($galaxyCluster)) {
                $galaxyClusterName = $galaxyCluster['GalaxyCluster']['value'];
            }
        }

        return [
            'tag_name' => $tag['Tag']['name'],
            'is_galaxy' => $tag['Tag']['is_galaxy'],
            'galaxy_cluster_name' => $galaxyClusterName,
        ];
    }

    /**
     * @param Model $model
     * @param array|null $fieldsToSave
     * @return array
     */
    private function changedFields(Model $model, $fieldsToSave = null)
    {
        $dbFields = $model->schema();
        $changedFields = [];
        foreach ($model->data[$model->alias] as $key => $value) {
            if (isset($this->skipFields[$key])) {
                continue;
            }
            if (!isset($dbFields[$key])) {
                continue;
            }
            if ($fieldsToSave && !in_array($key, $fieldsToSave, true)) {
                continue;
            }

            if (isset($model->data[$model->alias][$model->primaryKey]) && isset($this->old[$model->alias][$key])) {
                $old = $this->old[$model->alias][$key];
            } else {
                $old = null;
            }

            // Normalize
            if (is_bool($old)) {
                $old = $old ? 1 : 0;
            }
            if (is_bool($value)) {
                $value = $value ? 1 : 0;
            }
            $dbType = $dbFields[$key]['type'];
            if ($dbType === 'integer' || $dbType === 'tinyinteger' || $dbType === 'biginteger' || $dbType === 'boolean') {
                $value = (int)$value;
                if ($old !== null) {
                    $old = (int)$old;
                }
            }

            if ($value == $old) {
                continue;
            }

            if ($key === 'password' || $key === 'authkey') {
                $value = '*****';
                if ($old !== null) {
                    $old = $value;
                }
            }

            if ($old === null) {
                $changedFields[$key] = $value;
            } else {
                $changedFields[$key] = [$old, $value];
            }
        }

        return $changedFields;
    }

    /**
     * @return AuditLog
     */
    private function auditLog()
    {
        if ($this->AuditLog === null) {
            $this->AuditLog = ClassRegistry::init('AuditLog');
        }
        return $this->AuditLog;
    }
}
