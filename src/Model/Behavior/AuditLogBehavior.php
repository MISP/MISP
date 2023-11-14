<?php

namespace App\Model\Behavior;

use App\Model\Entity\AppModel;
use ArrayObject;
use Cake\Datasource\EntityInterface;
use Cake\Event\EventInterface;
use Cake\ORM\Behavior;
use Cake\ORM\TableRegistry;

class AuditLogBehavior extends Behavior
{
    /** @var array */
    private $config;

    /** @var array|null */
    private $old;

    /** @var AuditLog|null */
    private $AuditLogs;

    // Hash is faster that in_array
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
    ];

    public function initialize(array $config): void
    {
        $this->config = $config;
    }

    public function beforeSave(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        $fields = $entity->extract($entity->getVisible(), true);
        $skipFields = $this->skipFields;
        $fieldsToFetch = array_filter(
            $fields,
            function ($key) use ($skipFields) {
                return strpos($key, '_') !== 0 && !isset($skipFields[$key]);
            },
            ARRAY_FILTER_USE_KEY
        );
        // Do not fetch old version when just few fields will be fetched
        $fieldToFetch = [];
        if (!empty($options['fieldList'])) {
            foreach ($options['fieldList'] as $field) {
                if (!isset($this->skipFields[$field])) {
                    $fieldToFetch[] = $field;
                }
            }
            if (empty($fieldToFetch)) {
                $this->old = null;
                return true;
            }
        }
        if ($entity->id) {
            $this->old = $this->_table->find()->where(['id' => $entity->id])->contain($fieldToFetch)->first();
        } else {
            $this->old = null;
        }
        return true;
    }

    public function afterSave(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        if ($entity->id) {
            $id = $entity->id;
        } else {
            $id = null;
        }

        if ($entity->isNew()) {
            $action = AppModel::ACTION_ADD;
        } else {
            $action = AppModel::ACTION_EDIT;
            if (isset($entity['deleted'])) {
                if ($entity['deleted']) {
                    $action = AppModel::ACTION_SOFT_DELETE;
                } else if (!$entity['deleted'] && $this->old['deleted']) {
                    $action = AppModel::ACTION_UNDELETE;
                }
            }
        }
        $changedFields = $this->changedFields($entity, isset($options['fieldList']) ? $options['fieldList'] : null);
        if (empty($changedFields)) {
            return;
        }

        $modelTitleField = $this->_table->getDisplayField();
        if (is_callable($modelTitleField)) {
            $modelTitle = $modelTitleField($entity, isset($this->old) ? $this->old : []);
        } else if (isset($entity[$modelTitleField])) {
            $modelTitle = $entity[$modelTitleField];
        } else if (!empty($this->old) && $this->old[$modelTitleField]) {
            $modelTitle = $this->old[$modelTitleField];
        } else {
            $modelTitle = '';
        }
        $this->auditLogs()->insert(
            [
                'request_action' => $action,
                'model' => $entity->getSource(),
                'model_id' => $id,
                'model_title' => $modelTitle,
                'changed' => $changedFields
            ]
        );
    }

    public function beforeDelete(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        $this->old = $this->_table->find()->where(['id' => $entity->id])->first();
        return true;
    }

    public function afterDelete(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        $modelTitleField = $this->_table->getDisplayField();
        if (is_callable($modelTitleField)) {
            $modelTitle = $modelTitleField($entity, []);
        } else if (isset($entity[$modelTitleField])) {
            $modelTitle = $entity[$modelTitleField];
        }

        $this->auditLogs()->insert(
            [
                'request_action' => AppModel::ACTION_DELETE,
                'model' => $entity->getSource(),
                'model_id' => $this->old->id,
                'model_title' => $modelTitle,
                'changed' => $this->changedFields($entity)
            ]
        );
    }

    /**
     * @param Model $model
     * @param array|null $fieldsToSave
     * @return array
     */
    private function changedFields(EntityInterface $entity, $fieldsToSave = null)
    {
        $dbFields = $this->_table->getSchema()->typeMap();
        $changedFields = [];
        foreach ($entity->extract($entity->getVisible()) as $key => $value) {
            if (isset($this->skipFields[$key])) {
                continue;
            }
            if (!isset($dbFields[$key])) {
                continue;
            }
            if ($fieldsToSave && !in_array($key, $fieldsToSave, true)) {
                continue;
            }
            if (isset($entity[$key]) && isset($this->old[$key])) {
                $old = $this->old[$key];
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
            $dbType = $dbFields[$key];
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
     * @return AuditLogs
     */
    public function auditLogs()
    {
        if ($this->AuditLogs === null) {
            $this->AuditLogs = TableRegistry::getTableLocator()->get('AuditLogs');
        }
        return $this->AuditLogs;
    }

    public function log()
    {
    }
}
