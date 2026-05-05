<?php
App::uses('AppModel', 'Model');

/**
 * EventTemplateObjectDependency — sidecar index for EventTemplate.
 *
 * One row per (event_template_id, distinct object_template_uuid) pair.
 * Rows are regenerated in EventTemplate::afterSave() by walking the template's
 * JSON definition; this table exists only to make "which event templates
 * depend on object template X?" a cheap relational query rather than an
 * in-memory scan of every template's JSON blob.
 *
 * See docs/dev/event-templating-prd.md §6.2.
 */
class EventTemplateObjectDependency extends AppModel
{
    public $belongsTo = array(
        'EventTemplate' => array(
            'className' => 'EventTemplate',
            'foreignKey' => 'event_template_id',
        ),
    );

    public $validate = array(
        'event_template_id' => array(
            'rule' => 'naturalNumber',
            'message' => 'event_template_id is required',
        ),
        'object_template_uuid' => array(
            'notBlank' => array(
                'rule' => 'notBlank',
                'message' => 'object_template_uuid is required',
            ),
            'uuid' => array(
                'rule' => 'uuid',
                'message' => 'object_template_uuid must be a valid UUID',
            ),
        ),
        'object_template_name' => array(
            'rule' => 'notBlank',
            'message' => 'object_template_name is required',
        ),
        'minimum_version' => array(
            'rule' => 'naturalNumber',
            'message' => 'minimum_version is required',
        ),
    );
}
