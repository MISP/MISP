<?php

class InitialMigration extends Phinx\Migration\AbstractMigration
{
    public function up()
    {
        $this->table('posts')
            ->addColumn('date_created', 'datetime', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('date_modified', 'datetime', [
                'null' => false,
                'after' => 'date_created',
            ])
            ->addColumn('user_id', 'integer', [
                'null' => false,
                'after' => 'date_modified',
            ])
            ->addColumn('contents', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'user_id',
            ])
            ->addColumn('post_id', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'contents',
            ])
            ->addColumn('thread_id', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'post_id',
            ])
            ->addIndex(['post_id'], [
                'name' => 'posts_post_id',
                'unique' => false,
            ])
            ->addIndex(['thread_id'], [
                'name' => 'posts_thread_id',
                'unique' => false,
            ])
            ->create();
        $this->table('templates')
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'id',
            ])
            ->addColumn('description', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'name',
            ])
            ->addColumn('org', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'description',
            ])
            ->addColumn('share', 'boolean', [
                'null' => false,
                'after' => 'org',
            ])
            ->create();
        $this->table('template_elements')
            ->addColumn('template_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('position', 'integer', [
                'null' => false,
                'after' => 'template_id',
            ])
            ->addColumn('element_definition', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'position',
            ])
            ->create();
        $this->table('threat_levels')
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 50,
                'after' => 'id',
            ])
            ->addColumn('description', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'name',
            ])
            ->addColumn('form_description', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'description',
            ])
            ->create();
        $this->table('threads')
            ->addColumn('date_created', 'datetime', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('date_modified', 'datetime', [
                'null' => false,
                'after' => 'date_created',
            ])
            ->addColumn('distribution', 'integer', [
                'null' => false,
                'after' => 'date_modified',
            ])
            ->addColumn('user_id', 'integer', [
                'null' => false,
                'after' => 'distribution',
            ])
            ->addColumn('post_count', 'integer', [
                'null' => false,
                'after' => 'user_id',
            ])
            ->addColumn('event_id', 'integer', [
                'null' => false,
                'after' => 'post_count',
            ])
            ->addColumn('title', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'event_id',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'after' => 'title',
            ])
            ->addColumn('sharing_group_id', 'integer', [
                'null' => false,
                'after' => 'org_id',
            ])
            ->addIndex(['user_id'], [
                'name' => 'threads_user_id',
                'unique' => false,
            ])
            ->addIndex(['event_id'], [
                'name' => 'threads_event_id',
                'unique' => false,
            ])
            ->addIndex(['org_id'], [
                'name' => 'threads_org_id',
                'unique' => false,
            ])
            ->addIndex(['sharing_group_id'], [
                'name' => 'threads_sharing_group_id',
                'unique' => false,
            ])
            ->create();
        $this->table('event_tags')
            ->addColumn('event_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('tag_id', 'integer', [
                'null' => false,
                'after' => 'event_id',
            ])
            ->addColumn('local', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'tag_id',
            ])
            ->addColumn('relationship_type', 'string', [
                'null' => true,
                'default' => '',
                'limit' => 191,
                'after' => 'local',
            ])
            ->addIndex(['event_id'], [
                'name' => 'event_tags_event_id',
                'unique' => false,
            ])
            ->addIndex(['tag_id'], [
                'name' => 'event_tags_tag_id',
                'unique' => false,
            ])
            ->create();
        $this->table('template_element_texts')
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'id',
            ])
            ->addColumn('template_element_id', 'integer', [
                'null' => false,
                'after' => 'name',
            ])
            ->addColumn('text', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'template_element_id',
            ])
            ->create();
        $this->table('tags')
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'id',
            ])
            ->addColumn('colour', 'string', [
                'null' => false,
                'limit' => 7,
                'after' => 'name',
            ])
            ->addColumn('exportable', 'boolean', [
                'null' => false,
                'after' => 'colour',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'exportable',
            ])
            ->addColumn('user_id', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'org_id',
            ])
            ->addColumn('hide_tag', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'user_id',
            ])
            ->addColumn('numerical_value', 'integer', [
                'null' => true,
                'default' => null,
                'after' => 'hide_tag',
            ])
            ->addColumn('is_galaxy', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'numerical_value',
            ])
            ->addColumn('is_custom_galaxy', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'is_galaxy',
            ])
            ->addColumn('local_only', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'is_custom_galaxy',
            ])
            ->addIndex(['name'], [
                'name' => 'tags_name',
                'unique' => true,
            ])
            ->addIndex(['org_id'], [
                'name' => 'tags_org_id',
                'unique' => false,
            ])
            ->addIndex(['user_id'], [
                'name' => 'tags_user_id',
                'unique' => false,
            ])
            ->addIndex(['numerical_value'], [
                'name' => 'tags_numerical_value',
                'unique' => false,
            ])
            ->create();
        $this->table('tasks')
            ->addColumn('type', 'string', [
                'null' => false,
                'limit' => 100,
                'after' => 'id',
            ])
            ->addColumn('timer', 'integer', [
                'null' => false,
                'after' => 'type',
            ])
            ->addColumn('scheduled_time', 'string', [
                'null' => false,
                'default' => '6:00',
                'limit' => 8,
                'after' => 'timer',
            ])
            ->addColumn('process_id', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 32,
            ])
            ->addColumn('description', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'process_id',
            ])
            ->addColumn('next_execution_time', 'integer', [
                'null' => false,
                'after' => 'description',
            ])
            ->addColumn('message', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'next_execution_time',
            ])
            ->create();
        $this->table('template_element_attributes')
            ->addColumn('template_element_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'template_element_id',
            ])
            ->addColumn('description', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'name',
            ])
            ->addColumn('to_ids', 'boolean', [
                'null' => false,
                'default' => '1',
                'after' => 'description',
            ])
            ->addColumn('category', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'to_ids',
            ])
            ->addColumn('complex', 'boolean', [
                'null' => false,
                'after' => 'category',
            ])
            ->addColumn('type', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'complex',
            ])
            ->addColumn('mandatory', 'boolean', [
                'null' => false,
                'after' => 'type',
            ])
            ->addColumn('batch', 'boolean', [
                'null' => false,
                'after' => 'mandatory',
            ])
            ->create();
        $this->table('jobs')
            ->addColumn('worker', 'string', [
                'null' => false,
                'limit' => 32,
                'after' => 'id',
            ])
            ->addColumn('job_type', 'string', [
                'null' => false,
                'limit' => 32,
                'after' => 'worker',
            ])
            ->addColumn('job_input', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'job_type',
            ])
            ->addColumn('status', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'job_input',
            ])
            ->addColumn('retries', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'status',
            ])
            ->addColumn('message', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'retries',
            ])
            ->addColumn('progress', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'message',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'progress',
            ])
            ->addColumn('process_id', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 36,
                'after' => 'org_id',
            ])
            ->addColumn('date_created', 'datetime', [
                'null' => false,
                'after' => 'process_id',
            ])
            ->addColumn('date_modified', 'datetime', [
                'null' => false,
                'after' => 'date_created',
            ])
            ->create();
        $this->table('template_element_files')
            ->addColumn('template_element_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'template_element_id',
            ])
            ->addColumn('description', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'name',
            ])
            ->addColumn('category', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'description',
            ])
            ->addColumn('malware', 'boolean', [
                'null' => false,
                'after' => 'category',
            ])
            ->addColumn('mandatory', 'boolean', [
                'null' => false,
                'after' => 'malware',
            ])
            ->addColumn('batch', 'boolean', [
                'null' => false,
                'after' => 'mandatory',
            ])
            ->create();
        $this->table('template_tags')
            ->addColumn('template_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('tag_id', 'integer', [
                'null' => false,
                'after' => 'template_id',
            ])
            ->create();
        $this->table('attribute_tags')
            ->addColumn('attribute_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('event_id', 'integer', [
                'null' => false,
                'after' => 'attribute_id',
            ])
            ->addColumn('tag_id', 'integer', [
                'null' => false,
                'after' => 'event_id',
            ])
            ->addColumn('local', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'tag_id',
            ])
            ->addColumn('relationship_type', 'string', [
                'null' => true,
                'default' => '',
                'limit' => 191,
                'after' => 'local',
            ])
            ->addIndex(['attribute_id'], [
                'name' => 'attribute_tags_attribute_id',
                'unique' => false,
            ])
            ->addIndex(['event_id'], [
                'name' => 'attribute_tags_event_id',
                'unique' => false,
            ])
            ->addIndex(['tag_id'], [
                'name' => 'attribute_tags_tag_id',
                'unique' => false,
            ])
            ->create();
        $this->table('warninglist_entries')
            ->addColumn('value', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'id',
            ])
            ->addColumn('warninglist_id', 'integer', [
                'null' => false,
                'after' => 'value',
            ])
            ->addColumn('comment', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'warninglist_id',
            ])
            ->addIndex(['warninglist_id'], [
                'name' => 'warninglist_entries_warninglist_id',
                'unique' => false,
            ])
            ->create();
        $this->table('event_locks')
            ->addColumn('event_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('user_id', 'integer', [
                'null' => false,
                'after' => 'event_id',
            ])
            ->addColumn('timestamp', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'user_id',
            ])
            ->addIndex(['event_id'], [
                'name' => 'event_locks_event_id',
                'unique' => false,
            ])
            ->addIndex(['user_id'], [
                'name' => 'event_locks_user_id',
                'unique' => false,
            ])
            ->addIndex(['timestamp'], [
                'name' => 'event_locks_timestamp',
                'unique' => false,
            ])
            ->create();
        $this->table('rest_client_histories')
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('user_id', 'integer', [
                'null' => false,
                'after' => 'org_id',
            ])
            ->addColumn('headers', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'user_id',
            ])
            ->addColumn('body', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'headers',
            ])
            ->addColumn('url', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'body',
            ])
            ->addColumn('http_method', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'url',
            ])
            ->addColumn('timestamp', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'http_method',
            ])
            ->addColumn('use_full_path', 'boolean', [
                'null' => true,
                'default' => 0,
                'after' => 'timestamp',
            ])
            ->addColumn('show_result', 'boolean', [
                'null' => true,
                'default' => 0,
                'after' => 'use_full_path',
            ])
            ->addColumn('skip_ssl', 'boolean', [
                'null' => true,
                'default' => 0,
                'after' => 'show_result',
            ])
            ->addColumn('outcome', 'integer', [
                'null' => false,
                'after' => 'skip_ssl',
            ])
            ->addColumn('bookmark', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'outcome',
            ])
            ->addColumn('bookmark_name', 'string', [
                'null' => true,
                'default' => '',
                'limit' => 255,
                'after' => 'bookmark',
            ])
            ->addIndex(['org_id'], [
                'name' => 'rest_client_histories_org_id',
                'unique' => false,
            ])
            ->addIndex(['user_id'], [
                'name' => 'rest_client_histories_user_id',
                'unique' => false,
            ])
            ->addIndex(['timestamp'], [
                'name' => 'rest_client_histories_timestamp',
                'unique' => false,
            ])
            ->create();
        $this->table('object_templates')
            ->addColumn('user_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'after' => 'user_id',
            ])
            ->addColumn('uuid', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 40,
                'after' => 'org_id',
            ])
            ->addColumn('name', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'uuid',
            ])
            ->addColumn('meta-category', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'name',
            ])
            ->addColumn('description', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'meta-category',
            ])
            ->addColumn('version', 'integer', [
                'null' => false,
                'after' => 'description',
            ])
            ->addColumn('requirements', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'version',
            ])
            ->addColumn('fixed', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'requirements',
            ])
            ->addColumn('active', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'fixed',
            ])
            ->addIndex(['user_id'], [
                'name' => 'object_templates_user_id',
                'unique' => false,
            ])
            ->addIndex(['org_id'], [
                'name' => 'object_templates_org_id',
                'unique' => false,
            ])
            ->addIndex(['uuid'], [
                'name' => 'object_templates_uuid',
                'unique' => false,
            ])
            ->addIndex(['name'], [
                'name' => 'object_templates_name',
                'unique' => false,
            ])
            ->addIndex(['meta-category'], [
                'name' => 'object_templates_meta-category',
                'unique' => false,
            ])
            ->create();
        $this->table('shadow_attribute_correlations')
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('value', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'org_id',
            ])
            ->addColumn('distribution', 'integer', [
                'null' => false,
                'after' => 'value',
            ])
            ->addColumn('a_distribution', 'integer', [
                'null' => false,
                'after' => 'distribution',
            ])
            ->addColumn('sharing_group_id', 'integer', [
                'null' => true,
                'default' => null,
                'after' => 'a_distribution',
            ])
            ->addColumn('a_sharing_group_id', 'integer', [
                'null' => true,
                'default' => null,
                'after' => 'sharing_group_id',
            ])
            ->addColumn('attribute_id', 'integer', [
                'null' => false,
                'after' => 'a_sharing_group_id',
            ])
            ->addColumn('1_shadow_attribute_id', 'integer', [
                'null' => false,
                'after' => 'attribute_id',
            ])
            ->addColumn('event_id', 'integer', [
                'null' => false,
                'after' => '1_shadow_attribute_id',
            ])
            ->addColumn('1_event_id', 'integer', [
                'null' => false,
                'after' => 'event_id',
            ])
            ->addColumn('info', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => '1_event_id',
            ])
            ->addIndex(['org_id'], [
                'name' => 'shadow_attribute_correlations_org_id',
                'unique' => false,
            ])
            ->addIndex(['attribute_id'], [
                'name' => 'shadow_attribute_correlations_attribute_id',
                'unique' => false,
            ])
            ->addIndex(['a_sharing_group_id'], [
                'name' => 'shadow_attribute_correlations_a_sharing_group_id',
                'unique' => false,
            ])
            ->addIndex(['event_id'], [
                'name' => 'shadow_attribute_correlations_event_id',
                'unique' => false,
            ])
            ->addIndex(['1_event_id'], [
                'name' => 'shadow_attribute_correlations_1_event_id',
                'unique' => false,
            ])
            ->addIndex(['sharing_group_id'], [
                'name' => 'shadow_attribute_correlations_sharing_group_id',
                'unique' => false,
            ])
            ->addIndex(['1_shadow_attribute_id'], [
                'name' => 'shadow_attribute_correlations_1_shadow_attribute_id',
                'unique' => false,
            ])
            ->create();
        $this->table('event_delegations')
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('requester_org_id', 'integer', [
                'null' => false,
                'after' => 'org_id',
            ])
            ->addColumn('event_id', 'integer', [
                'null' => false,
                'after' => 'requester_org_id',
            ])
            ->addColumn('message', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'event_id',
            ])
            ->addColumn('distribution', 'integer', [
                'null' => false,
                'default' => '-1',
                'after' => 'message',
            ])
            ->addColumn('sharing_group_id', 'integer', [
                'null' => true,
                'default' => null,
                'after' => 'distribution',
            ])
            ->addIndex(['org_id'], [
                'name' => 'event_delegations_org_id',
                'unique' => false,
            ])
            ->addIndex(['event_id'], [
                'name' => 'event_delegations_event_id',
                'unique' => false,
            ])
            ->create();
        $this->table('decaying_models')
            ->addColumn('uuid', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'uuid',
            ])
            ->addColumn('parameters', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'name',
            ])
            ->addColumn('attribute_types', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'parameters',
            ])
            ->addColumn('description', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'attribute_types',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => true,
                'default' => null,
                'after' => 'description',
            ])
            ->addColumn('enabled', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'org_id',
            ])
            ->addColumn('all_orgs', 'boolean', [
                'null' => false,
                'default' => '1',
                'after' => 'enabled',
            ])
            ->addColumn('ref', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'all_orgs',
            ])
            ->addColumn('formula', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'ref',
            ])
            ->addColumn('version', 'string', [
                'null' => false,
                'default' => '',
                'limit' => 255,
                'after' => 'formula',
            ])
            ->addColumn('default', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'version',
            ])
            ->addIndex(['uuid'], [
                'name' => 'decaying_models_uuid',
                'unique' => false,
            ])
            ->addIndex(['name'], [
                'name' => 'decaying_models_name',
                'unique' => false,
            ])
            ->addIndex(['org_id'], [
                'name' => 'decaying_models_org_id',
                'unique' => false,
            ])
            ->addIndex(['enabled'], [
                'name' => 'decaying_models_enabled',
                'unique' => false,
            ])
            ->addIndex(['all_orgs'], [
                'name' => 'decaying_models_all_orgs',
                'unique' => false,
            ])
            ->addIndex(['version'], [
                'name' => 'decaying_models_version',
                'unique' => false,
            ])
            ->create();
        $this->table('warninglist_types')
            ->addColumn('type', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'id',
            ])
            ->addColumn('warninglist_id', 'integer', [
                'null' => false,
                'after' => 'type',
            ])
            ->create();
        $this->table('news')
            ->addColumn('message', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'id',
            ])
            ->addColumn('title', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'message',
            ])
            ->addColumn('user_id', 'integer', [
                'null' => false,
                'after' => 'title',
            ])
            ->addColumn('date_created', 'integer', [
                'null' => false,
                'signed' => false,
                'after' => 'user_id',
            ])
            ->create();
        $this->table('favourite_tags')
            ->addColumn('tag_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('user_id', 'integer', [
                'null' => false,
                'after' => 'tag_id',
            ])
            ->addIndex(['user_id'], [
                'name' => 'favourite_tags_user_id',
                'unique' => false,
            ])
            ->addIndex(['tag_id'], [
                'name' => 'favourite_tags_tag_id',
                'unique' => false,
            ])
            ->create();
        $this->table('noticelist_entries')
            ->addColumn('noticelist_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('data', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'noticelist_id',
            ])
            ->addIndex(['noticelist_id'], [
                'name' => 'noticelist_entries_noticelist_id',
                'unique' => false,
            ])
            ->create();
        $this->table('warninglists')
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'id',
            ])
            ->addColumn('type', 'string', [
                'null' => false,
                'default' => 'string',
                'limit' => 255,
                'after' => 'name',
            ])
            ->addColumn('description', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'type',
            ])
            ->addColumn('version', 'integer', [
                'null' => false,
                'default' => '1',
                'after' => 'description',
            ])
            ->addColumn('enabled', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'version',
            ])
            ->addColumn('default', 'boolean', [
                'null' => false,
                'default' => '1',
                'after' => 'enabled',
            ])
            ->addColumn('category', 'string', [
                'null' => false,
                'default' => 'false_positive',
                'limit' => 20,
                'after' => 'default',
            ])
            ->create();
        $this->table('feeds')
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'id',
            ])
            ->addColumn('provider', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'name',
            ])
            ->addColumn('url', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'provider',
            ])
            ->addColumn('rules', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'url',
            ])
            ->addColumn('enabled', 'boolean', [
                'null' => true,
                'default' => 0,
                'after' => 'rules',
            ])
            ->addColumn('distribution', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'enabled',
            ])
            ->addColumn('sharing_group_id', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'distribution',
            ])
            ->addColumn('tag_id', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'sharing_group_id',
            ])
            ->addColumn('default', 'boolean', [
                'null' => true,
                'default' => 0,
                'after' => 'tag_id',
            ])
            ->addColumn('source_format', 'string', [
                'null' => true,
                'default' => 'misp',
                'limit' => 255,
                'after' => 'default',
            ])
            ->addColumn('fixed_event', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'source_format',
            ])
            ->addColumn('delta_merge', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'fixed_event',
            ])
            ->addColumn('event_id', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'delta_merge',
            ])
            ->addColumn('publish', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'event_id',
            ])
            ->addColumn('override_ids', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'publish',
            ])
            ->addColumn('settings', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'override_ids',
            ])
            ->addColumn('input_source', 'string', [
                'null' => false,
                'default' => 'network',
                'limit' => 255,
                'after' => 'settings',
            ])
            ->addColumn('delete_local_file', 'boolean', [
                'null' => true,
                'default' => 0,
                'after' => 'input_source',
            ])
            ->addColumn('lookup_visible', 'boolean', [
                'null' => true,
                'default' => 0,
                'after' => 'delete_local_file',
            ])
            ->addColumn('headers', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'lookup_visible',
            ])
            ->addColumn('caching_enabled', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'headers',
            ])
            ->addColumn('force_to_ids', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'caching_enabled',
            ])
            ->addColumn('orgc_id', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'force_to_ids',
            ])
            ->addColumn('tag_collection_id', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'orgc_id',
            ])
            ->addIndex(['input_source'], [
                'name' => 'feeds_input_source',
                'unique' => false,
            ])
            ->addIndex(['orgc_id'], [
                'name' => 'feeds_orgc_id',
                'unique' => false,
            ])
            ->create();
        $this->table('tag_collections')
            ->addColumn('uuid', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('user_id', 'integer', [
                'null' => false,
                'after' => 'uuid',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'after' => 'user_id',
            ])
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'org_id',
            ])
            ->addColumn('description', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'name',
            ])
            ->addColumn('all_orgs', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'description',
            ])
            ->addIndex(['uuid'], [
                'name' => 'tag_collections_uuid',
                'unique' => true,
            ])
            ->addIndex(['user_id'], [
                'name' => 'tag_collections_user_id',
                'unique' => false,
            ])
            ->addIndex(['org_id'], [
                'name' => 'tag_collections_org_id',
                'unique' => false,
            ])
            ->create();
        $this->table('object_relationships')
            ->addColumn('version', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('name', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'version',
            ])
            ->addColumn('description', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'name',
            ])
            ->addColumn('format', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'description',
            ])
            ->addIndex(['name'], [
                'name' => 'object_relationships_name',
                'unique' => false,
            ])
            ->create();
        $this->table('object_references')
            ->addColumn('uuid', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('timestamp', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'uuid',
            ])
            ->addColumn('object_id', 'integer', [
                'null' => false,
                'after' => 'timestamp',
            ])
            ->addColumn('event_id', 'integer', [
                'null' => false,
                'after' => 'object_id',
            ])
            ->addColumn('source_uuid', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 40,
                'after' => 'event_id',
            ])
            ->addColumn('referenced_uuid', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 40,
                'after' => 'source_uuid',
            ])
            ->addColumn('referenced_id', 'integer', [
                'null' => false,
                'after' => 'referenced_uuid',
            ])
            ->addColumn('referenced_type', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'referenced_id',
            ])
            ->addColumn('relationship_type', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'referenced_type',
            ])
            ->addColumn('comment', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'relationship_type',
            ])
            ->addColumn('deleted', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'comment',
            ])
            ->addIndex(['uuid'], [
                'name' => 'object_references_uuid',
                'unique' => true,
            ])
            ->addIndex(['object_id'], [
                'name' => 'object_references_object_id',
                'unique' => false,
            ])
            ->addIndex(['referenced_id'], [
                'name' => 'object_references_referenced_id',
                'unique' => false,
            ])
            ->addIndex(['event_id'], [
                'name' => 'object_references_event_id',
                'unique' => false,
            ])
            ->create();
        $this->table('fuzzy_correlate_ssdeep')
            ->addColumn('chunk', 'string', [
                'null' => false,
                'limit' => 12,
                'after' => 'id',
            ])
            ->addColumn('attribute_id', 'integer', [
                'null' => false,
                'after' => 'chunk',
            ])
            ->addIndex(['chunk'], [
                'name' => 'fuzzy_correlate_ssdeep_chunk',
                'unique' => false,
            ])
            ->addIndex(['attribute_id'], [
                'name' => 'fuzzy_correlate_ssdeep_attribute_id',
                'unique' => false,
            ])
            ->create();
        $this->table('noticelists')
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'id',
            ])
            ->addColumn('expanded_name', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'name',
            ])
            ->addColumn('ref', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'expanded_name',
            ])
            ->addColumn('geographical_area', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'ref',
            ])
            ->addColumn('version', 'integer', [
                'null' => false,
                'default' => '1',
                'after' => 'geographical_area',
            ])
            ->addColumn('enabled', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'version',
            ])
            ->addIndex(['name'], [
                'name' => 'noticelists_name',
                'unique' => false,
            ])
            ->addIndex(['geographical_area'], [
                'name' => 'noticelists_geographical_area',
                'unique' => false,
            ])
            ->create();
        $this->table('event_graph')
            ->addColumn('event_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('user_id', 'integer', [
                'null' => false,
                'after' => 'event_id',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'after' => 'user_id',
            ])
            ->addColumn('timestamp', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'org_id',
            ])
            ->addColumn('network_name', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'timestamp',
            ])
            ->addColumn('network_json', 'text', [
                'null' => false,
                'after' => 'network_name',
            ])
            ->addColumn('preview_img', 'text', [
                'null' => true,
                'default' => null,
                'after' => 'network_json',
            ])
            ->addIndex(['event_id'], [
                'name' => 'event_graph_event_id',
                'unique' => false,
            ])
            ->addIndex(['user_id'], [
                'name' => 'event_graph_user_id',
                'unique' => false,
            ])
            ->addIndex(['org_id'], [
                'name' => 'event_graph_org_id',
                'unique' => false,
            ])
            ->addIndex(['timestamp'], [
                'name' => 'event_graph_timestamp',
                'unique' => false,
            ])
            ->create();
        $this->table('decaying_model_mappings')
            ->addColumn('attribute_type', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'id',
            ])
            ->addColumn('model_id', 'integer', [
                'null' => false,
                'after' => 'attribute_type',
            ])
            ->addIndex(['model_id'], [
                'name' => 'decaying_model_mappings_model_id',
                'unique' => false,
            ])
            ->create();
        $this->table('galaxy_cluster_relation_tags')
            ->addColumn('galaxy_cluster_relation_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('tag_id', 'integer', [
                'null' => false,
                'after' => 'galaxy_cluster_relation_id',
            ])
            ->addIndex(['galaxy_cluster_relation_id'], [
                'name' => 'galaxy_cluster_relation_tags_galaxy_cluster_relation_id',
                'unique' => false,
            ])
            ->addIndex(['tag_id'], [
                'name' => 'galaxy_cluster_relation_tags_tag_id',
                'unique' => false,
            ])
            ->create();
        $this->table('admin_settings')
            ->addColumn('setting', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'id',
            ])
            ->addColumn('value', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'setting',
            ])
            ->addIndex(['setting'], [
                'name' => 'admin_settings_setting',
                'unique' => true,
            ])
            ->create();
        $this->table('objects')
            ->addColumn('name', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'id',
            ])
            ->addColumn('meta-category', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'name',
            ])
            ->addColumn('description', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'meta-category',
            ])
            ->addColumn('template_uuid', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 40,
                'after' => 'description',
            ])
            ->addColumn('template_version', 'integer', [
                'null' => false,
                'after' => 'template_uuid',
            ])
            ->addColumn('event_id', 'integer', [
                'null' => false,
                'after' => 'template_version',
            ])
            ->addColumn('uuid', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 40,
                'after' => 'event_id',
            ])
            ->addColumn('timestamp', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'uuid',
            ])
            ->addColumn('distribution', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'timestamp',
            ])
            ->addColumn('sharing_group_id', 'integer', [
                'null' => true,
                'default' => null,
                'after' => 'distribution',
            ])
            ->addColumn('comment', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'sharing_group_id',
            ])
            ->addColumn('deleted', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'comment',
            ])
            ->addColumn('first_seen', 'biginteger', [
                'null' => true,
                'default' => null,
                'after' => 'deleted',
            ])
            ->addColumn('last_seen', 'biginteger', [
                'null' => true,
                'default' => null,
                'after' => 'first_seen',
            ])
            ->addIndex(['uuid'], [
                'name' => 'objects_uuid',
                'unique' => true,
            ])
            ->addIndex(['name'], [
                'name' => 'objects_name',
                'unique' => false,
            ])
            ->addIndex(['template_uuid'], [
                'name' => 'objects_template_uuid',
                'unique' => false,
            ])
            ->addIndex(['template_version'], [
                'name' => 'objects_template_version',
                'unique' => false,
            ])
            ->addIndex(['meta-category'], [
                'name' => 'objects_meta-category',
                'unique' => false,
            ])
            ->addIndex(['event_id'], [
                'name' => 'objects_event_id',
                'unique' => false,
            ])
            ->addIndex(['timestamp'], [
                'name' => 'objects_timestamp',
                'unique' => false,
            ])
            ->addIndex(['distribution'], [
                'name' => 'objects_distribution',
                'unique' => false,
            ])
            ->addIndex(['sharing_group_id'], [
                'name' => 'objects_sharing_group_id',
                'unique' => false,
            ])
            ->addIndex(['first_seen'], [
                'name' => 'objects_first_seen',
                'unique' => false,
            ])
            ->addIndex(['last_seen'], [
                'name' => 'objects_last_seen',
                'unique' => false,
            ])
            ->create();
        $this->table('tag_collection_tags')
            ->addColumn('tag_collection_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('tag_id', 'integer', [
                'null' => false,
                'after' => 'tag_collection_id',
            ])
            ->addIndex(['tag_collection_id'], [
                'name' => 'tag_collection_tags_tag_collection_id',
                'unique' => false,
            ])
            ->addIndex(['tag_id'], [
                'name' => 'tag_collection_tags_tag_id',
                'unique' => false,
            ])
            ->create();
        $this->table('object_template_elements')
            ->addColumn('object_template_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('object_relation', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'object_template_id',
            ])
            ->addColumn('type', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'object_relation',
            ])
            ->addColumn('ui-priority', 'integer', [
                'null' => false,
                'after' => 'type',
            ])
            ->addColumn('categories', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'ui-priority',
            ])
            ->addColumn('sane_default', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'categories',
            ])
            ->addColumn('values_list', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'sane_default',
            ])
            ->addColumn('description', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'values_list',
            ])
            ->addColumn('disable_correlation', 'boolean', [
                'null' => true,
                'default' => null,
                'after' => 'description',
            ])
            ->addColumn('multiple', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'disable_correlation',
            ])
            ->addIndex(['object_relation'], [
                'name' => 'object_template_elements_object_relation',
                'unique' => false,
            ])
            ->addIndex(['type'], [
                'name' => 'object_template_elements_type',
                'unique' => false,
            ])
            ->addIndex(['object_template_id'], [
                'name' => 'object_template_elements_object_template_id',
                'unique' => false,
            ])
            ->create();
        $this->table('user_settings')
            ->addColumn('setting', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'id',
            ])
            ->addColumn('value', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'setting',
            ])
            ->addColumn('user_id', 'integer', [
                'null' => false,
                'after' => 'value',
            ])
            ->addColumn('timestamp', 'integer', [
                'null' => false,
                'after' => 'user_id',
            ])
            ->addIndex(['user_id', 'setting'], [
                'name' => 'user_settings_unique_setting',
                'unique' => true,
            ])
            ->addIndex(['setting'], [
                'name' => 'user_settings_setting',
                'unique' => false,
            ])
            ->addIndex(['user_id'], [
                'name' => 'user_settings_user_id',
                'unique' => false,
            ])
            ->create();
        $this->table('allowedlist')
            ->addColumn('name', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'id',
            ])
            ->create();
        $this->table('bookmarks')
            ->addColumn('user_id', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => 'id',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => 'user_id',
            ])
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 191,
                'after' => 'org_id',
            ])
            ->addColumn('url', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'name',
            ])
            ->addColumn('exposed_to_org', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'url',
            ])
            ->addColumn('comment', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'exposed_to_org',
            ])
            ->addIndex(['user_id'], [
                'name' => 'bookmarks_user_id',
                'unique' => false,
            ])
            ->addIndex(['org_id'], [
                'name' => 'bookmarks_org_id',
                'unique' => false,
            ])
            ->addIndex(['name'], [
                'name' => 'bookmarks_name',
                'unique' => false,
            ])
            ->create();
        $this->table('taxonomy_entries')
            ->addColumn('taxonomy_predicate_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('value', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'taxonomy_predicate_id',
            ])
            ->addColumn('expanded', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'value',
            ])
            ->addColumn('colour', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 7,
                'after' => 'expanded',
            ])
            ->addColumn('description', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'colour',
            ])
            ->addColumn('numerical_value', 'integer', [
                'null' => true,
                'default' => null,
                'after' => 'description',
            ])
            ->addIndex(['taxonomy_predicate_id'], [
                'name' => 'taxonomy_entries_taxonomy_predicate_id',
                'unique' => false,
            ])
            ->addIndex(['numerical_value'], [
                'name' => 'taxonomy_entries_numerical_value',
                'unique' => false,
            ])
            ->create();
        $this->table('org_blocklists')
            ->addColumn('org_uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('created', 'datetime', [
                'null' => false,
                'after' => 'org_uuid',
            ])
            ->addColumn('org_name', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'created',
            ])
            ->addColumn('comment', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'org_name',
            ])
            ->addIndex(['org_uuid'], [
                'name' => 'org_blocklists_org_uuid',
                'unique' => true,
            ])
            ->addIndex(['org_name'], [
                'name' => 'org_blocklists_org_name',
                'unique' => false,
            ])
            ->create();
        $this->table('galaxies')
            ->addColumn('uuid', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'id',
            ])
            ->addColumn('name', 'string', [
                'null' => false,
                'default' => '',
                'limit' => 255,
                'after' => 'uuid',
            ])
            ->addColumn('type', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'name',
            ])
            ->addColumn('description', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'type',
            ])
            ->addColumn('version', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'description',
            ])
            ->addColumn('icon', 'string', [
                'null' => false,
                'default' => '',
                'limit' => 255,
                'after' => 'version',
            ])
            ->addColumn('namespace', 'string', [
                'null' => false,
                'default' => 'misp',
                'limit' => 255,
                'after' => 'icon',
            ])
            ->addColumn('enabled', 'boolean', [
                'null' => false,
                'default' => '1',
                'after' => 'namespace',
            ])
            ->addColumn('local_only', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'enabled',
            ])
            ->addColumn('kill_chain_order', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'local_only',
            ])
            ->addIndex(['uuid'], [
                'name' => 'galaxies_uuid',
                'unique' => true,
            ])
            ->addIndex(['name'], [
                'name' => 'galaxies_name',
                'unique' => false,
            ])
            ->addIndex(['type'], [
                'name' => 'galaxies_type',
                'unique' => false,
            ])
            ->addIndex(['namespace'], [
                'name' => 'galaxies_namespace',
                'unique' => false,
            ])
            ->create();
        $this->table('sighting_blocklists')
            ->addColumn('org_uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('created', 'datetime', [
                'null' => false,
                'after' => 'org_uuid',
            ])
            ->addColumn('org_name', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'created',
            ])
            ->addColumn('comment', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'org_name',
            ])
            ->addIndex(['org_uuid'], [
                'name' => 'sighting_blocklists_org_uuid',
                'unique' => false,
            ])
            ->addIndex(['org_name'], [
                'name' => 'sighting_blocklists_org_name',
                'unique' => false,
            ])
            ->create();
        $this->table('galaxy_cluster_relations')
            ->addColumn('galaxy_cluster_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('referenced_galaxy_cluster_id', 'integer', [
                'null' => false,
                'after' => 'galaxy_cluster_id',
            ])
            ->addColumn('referenced_galaxy_cluster_uuid', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'referenced_galaxy_cluster_id',
            ])
            ->addColumn('referenced_galaxy_cluster_type', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'referenced_galaxy_cluster_uuid',
            ])
            ->addColumn('galaxy_cluster_uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'referenced_galaxy_cluster_type',
            ])
            ->addColumn('distribution', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'galaxy_cluster_uuid',
            ])
            ->addColumn('sharing_group_id', 'integer', [
                'null' => true,
                'default' => null,
                'after' => 'distribution',
            ])
            ->addColumn('default', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'sharing_group_id',
            ])
            ->addIndex(['galaxy_cluster_id'], [
                'name' => 'galaxy_cluster_relations_galaxy_cluster_id',
                'unique' => false,
            ])
            ->addIndex(['referenced_galaxy_cluster_id'], [
                'name' => 'galaxy_cluster_relations_referenced_galaxy_cluster_id',
                'unique' => false,
            ])
            ->addIndex(['referenced_galaxy_cluster_type'], [
                'name' => 'galaxy_cluster_relations_referenced_galaxy_cluster_type',
                'unique' => false,
                'limit' => [
                    'referenced_galaxy_cluster_type' => 255,
                ],
            ])
            ->addIndex(['galaxy_cluster_uuid'], [
                'name' => 'galaxy_cluster_relations_galaxy_cluster_uuid',
                'unique' => false,
            ])
            ->addIndex(['sharing_group_id'], [
                'name' => 'galaxy_cluster_relations_sharing_group_id',
                'unique' => false,
            ])
            ->addIndex(['default'], [
                'name' => 'galaxy_cluster_relations_default',
                'unique' => false,
            ])
            ->create();
        $this->table('correlations')
            ->addColumn('value', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'id',
            ])
            ->addColumn('1_event_id', 'integer', [
                'null' => false,
                'after' => 'value',
            ])
            ->addColumn('1_attribute_id', 'integer', [
                'null' => false,
                'after' => '1_event_id',
            ])
            ->addColumn('event_id', 'integer', [
                'null' => false,
                'after' => '1_attribute_id',
            ])
            ->addColumn('attribute_id', 'integer', [
                'null' => false,
                'after' => 'event_id',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'after' => 'attribute_id',
            ])
            ->addColumn('distribution', 'integer', [
                'null' => false,
                'after' => 'org_id',
            ])
            ->addColumn('a_distribution', 'integer', [
                'null' => false,
                'after' => 'distribution',
            ])
            ->addColumn('sharing_group_id', 'integer', [
                'null' => false,
                'after' => 'a_distribution',
            ])
            ->addColumn('a_sharing_group_id', 'integer', [
                'null' => false,
                'after' => 'sharing_group_id',
            ])
            ->addIndex(['event_id'], [
                'name' => 'correlations_event_id',
                'unique' => false,
            ])
            ->addIndex(['1_event_id'], [
                'name' => 'correlations_1_event_id',
                'unique' => false,
            ])
            ->addIndex(['attribute_id'], [
                'name' => 'correlations_attribute_id',
                'unique' => false,
            ])
            ->addIndex(['1_attribute_id'], [
                'name' => 'correlations_1_attribute_id',
                'unique' => false,
            ])
            ->create();
        $this->table('shadow_attributes')
            ->addColumn('old_id', 'integer', [
                'null' => true,
                'default' => 0,
                'after' => 'id',
            ])
            ->addColumn('event_id', 'integer', [
                'null' => false,
                'after' => 'old_id',
            ])
            ->addColumn('type', 'string', [
                'null' => false,
                'limit' => 100,
                'after' => 'event_id',
            ])
            ->addColumn('category', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'type',
            ])
            ->addColumn('value1', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'category',
            ])
            ->addColumn('to_ids', 'boolean', [
                'null' => false,
                'default' => '1',
                'after' => 'value1',
            ])
            ->addColumn('uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'to_ids',
            ])
            ->addColumn('value2', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'uuid',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'after' => 'value2',
            ])
            ->addColumn('email', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'org_id',
            ])
            ->addColumn('event_org_id', 'integer', [
                'null' => false,
                'after' => 'email',
            ])
            ->addColumn('comment', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'event_org_id',
            ])
            ->addColumn('event_uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'comment',
            ])
            ->addColumn('deleted', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'event_uuid',
            ])
            ->addColumn('timestamp', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'deleted',
            ])
            ->addColumn('proposal_to_delete', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'timestamp',
            ])
            ->addColumn('disable_correlation', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'proposal_to_delete',
            ])
            ->addColumn('first_seen', 'biginteger', [
                'null' => true,
                'default' => null,
                'after' => 'disable_correlation',
            ])
            ->addColumn('last_seen', 'biginteger', [
                'null' => true,
                'default' => null,
                'after' => 'first_seen',
            ])
            ->addIndex(['event_id'], [
                'name' => 'shadow_attributes_event_id',
                'unique' => false,
            ])
            ->addIndex(['event_uuid'], [
                'name' => 'shadow_attributes_event_uuid',
                'unique' => false,
            ])
            ->addIndex(['event_org_id'], [
                'name' => 'shadow_attributes_event_org_id',
                'unique' => false,
            ])
            ->addIndex(['uuid'], [
                'name' => 'shadow_attributes_uuid',
                'unique' => false,
            ])
            ->addIndex(['old_id'], [
                'name' => 'shadow_attributes_old_id',
                'unique' => false,
            ])
            ->addIndex(['value1'], [
                'name' => 'shadow_attributes_value1',
                'unique' => false,
                'limit' => [
                    'value1' => 255,
                ],
            ])
            ->addIndex(['value2'], [
                'name' => 'shadow_attributes_value2',
                'unique' => false,
                'limit' => [
                    'value2' => 255,
                ],
            ])
            ->addIndex(['type'], [
                'name' => 'shadow_attributes_type',
                'unique' => false,
            ])
            ->addIndex(['category'], [
                'name' => 'shadow_attributes_category',
                'unique' => false,
            ])
            ->addIndex(['first_seen'], [
                'name' => 'shadow_attributes_first_seen',
                'unique' => false,
            ])
            ->addIndex(['last_seen'], [
                'name' => 'shadow_attributes_last_seen',
                'unique' => false,
            ])
            ->create();
        $this->table('sharing_group_servers')
            ->addColumn('sharing_group_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('server_id', 'integer', [
                'null' => false,
                'after' => 'sharing_group_id',
            ])
            ->addColumn('all_orgs', 'boolean', [
                'null' => false,
                'after' => 'server_id',
            ])
            ->addIndex(['server_id'], [
                'name' => 'sharing_group_servers_server_id',
                'unique' => false,
            ])
            ->addIndex(['sharing_group_id'], [
                'name' => 'sharing_group_servers_sharing_group_id',
                'unique' => false,
            ])
            ->create();
        $this->table('galaxy_cluster_blocklists')
            ->addColumn('cluster_uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('created', 'datetime', [
                'null' => false,
                'after' => 'cluster_uuid',
            ])
            ->addColumn('cluster_info', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'created',
            ])
            ->addColumn('comment', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'cluster_info',
            ])
            ->addColumn('cluster_orgc', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'comment',
            ])
            ->addIndex(['cluster_uuid'], [
                'name' => 'galaxy_cluster_blocklists_cluster_uuid',
                'unique' => false,
            ])
            ->addIndex(['cluster_orgc'], [
                'name' => 'galaxy_cluster_blocklists_cluster_orgc',
                'unique' => false,
            ])
            ->create();
        $this->table('correlation_rules')
            ->addColumn('uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 191,
                'after' => 'uuid',
            ])
            ->addColumn('comment', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'name',
            ])
            ->addColumn('selector_type', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'comment',
            ])
            ->addColumn('selector_list', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'selector_type',
            ])
            ->addColumn('created', 'timestamp', [
                'null' => false,
                'default' => 'CURRENT_TIMESTAMP',
                'after' => 'selector_list',
            ])
            ->addColumn('timestamp', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'created',
            ])
            ->addIndex(['uuid'], [
                'name' => 'correlation_rules_uuid',
                'unique' => false,
            ])
            ->addIndex(['name'], [
                'name' => 'correlation_rules_name',
                'unique' => false,
            ])
            ->addIndex(['selector_type'], [
                'name' => 'correlation_rules_selector_type',
                'unique' => false,
            ])
            ->create();
        $this->table('taxonomies')
            ->addColumn('namespace', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'id',
            ])
            ->addColumn('description', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'namespace',
            ])
            ->addColumn('version', 'integer', [
                'null' => false,
                'after' => 'description',
            ])
            ->addColumn('enabled', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'version',
            ])
            ->addColumn('exclusive', 'boolean', [
                'null' => true,
                'default' => 0,
                'after' => 'enabled',
            ])
            ->addColumn('required', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'exclusive',
            ])
            ->addColumn('highlighted', 'boolean', [
                'null' => true,
                'default' => 0,
                'after' => 'required',
            ])
            ->create();
        $this->table('galaxy_clusters')
            ->addColumn('uuid', 'string', [
                'null' => false,
                'default' => '',
                'limit' => 255,
                'after' => 'id',
            ])
            ->addColumn('collection_uuid', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'uuid',
            ])
            ->addColumn('type', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'collection_uuid',
            ])
            ->addColumn('value', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'type',
            ])
            ->addColumn('tag_name', 'string', [
                'null' => false,
                'default' => '',
                'limit' => 255,
                'after' => 'value',
            ])
            ->addColumn('description', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'tag_name',
            ])
            ->addColumn('galaxy_id', 'integer', [
                'null' => false,
                'after' => 'description',
            ])
            ->addColumn('source', 'string', [
                'null' => false,
                'default' => '',
                'limit' => 255,
                'after' => 'galaxy_id',
            ])
            ->addColumn('authors', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'source',
            ])
            ->addColumn('version', 'integer', [
                'null' => true,
                'default' => 0,
                'after' => 'authors',
            ])
            ->addColumn('distribution', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'version',
            ])
            ->addColumn('sharing_group_id', 'integer', [
                'null' => true,
                'default' => null,
                'after' => 'distribution',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'after' => 'sharing_group_id',
            ])
            ->addColumn('orgc_id', 'integer', [
                'null' => false,
                'after' => 'org_id',
            ])
            ->addColumn('default', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'orgc_id',
            ])
            ->addColumn('locked', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'default',
            ])
            ->addColumn('extends_uuid', 'string', [
                'null' => true,
                'default' => '',
                'limit' => 40,
                'after' => 'locked',
            ])
            ->addColumn('extends_version', 'integer', [
                'null' => true,
                'default' => 0,
                'after' => 'extends_uuid',
            ])
            ->addColumn('published', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'extends_version',
            ])
            ->addColumn('deleted', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'published',
            ])
            ->addIndex(['value'], [
                'name' => 'galaxy_clusters_value',
                'unique' => false,
                'limit' => [
                    'value' => 255,
                ],
            ])
            ->addIndex(['uuid'], [
                'name' => 'galaxy_clusters_uuid',
                'unique' => false,
            ])
            ->addIndex(['collection_uuid'], [
                'name' => 'galaxy_clusters_collection_uuid',
                'unique' => false,
            ])
            ->addIndex(['galaxy_id'], [
                'name' => 'galaxy_clusters_galaxy_id',
                'unique' => false,
            ])
            ->addIndex(['version'], [
                'name' => 'galaxy_clusters_version',
                'unique' => false,
            ])
            ->addIndex(['tag_name'], [
                'name' => 'galaxy_clusters_tag_name',
                'unique' => false,
            ])
            ->addIndex(['type'], [
                'name' => 'galaxy_clusters_type',
                'unique' => false,
            ])
            ->addIndex(['org_id'], [
                'name' => 'galaxy_clusters_org_id',
                'unique' => false,
            ])
            ->addIndex(['orgc_id'], [
                'name' => 'galaxy_clusters_orgc_id',
                'unique' => false,
            ])
            ->addIndex(['sharing_group_id'], [
                'name' => 'galaxy_clusters_sharing_group_id',
                'unique' => false,
            ])
            ->addIndex(['extends_uuid'], [
                'name' => 'galaxy_clusters_extends_uuid',
                'unique' => false,
            ])
            ->addIndex(['extends_version'], [
                'name' => 'galaxy_clusters_extends_version',
                'unique' => false,
            ])
            ->addIndex(['default'], [
                'name' => 'galaxy_clusters_default',
                'unique' => false,
            ])
            ->create();
        $this->table('logs')
            ->addColumn('title', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'id',
            ])
            ->addColumn('created', 'datetime', [
                'null' => false,
                'after' => 'title',
            ])
            ->addColumn('model', 'string', [
                'null' => false,
                'limit' => 80,
                'after' => 'created',
            ])
            ->addColumn('model_id', 'integer', [
                'null' => false,
                'after' => 'model',
            ])
            ->addColumn('action', 'string', [
                'null' => false,
                'limit' => 20,
                'after' => 'model_id',
            ])
            ->addColumn('user_id', 'integer', [
                'null' => false,
                'after' => 'action',
            ])
            ->addColumn('change', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'user_id',
            ])
            ->addColumn('email', 'string', [
                'null' => false,
                'default' => '',
                'limit' => 255,
                'after' => 'change',
            ])
            ->addColumn('org', 'string', [
                'null' => false,
                'default' => '',
                'limit' => 255,
                'after' => 'email',
            ])
            ->addColumn('description', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'org',
            ])
            ->addColumn('ip', 'string', [
                'null' => false,
                'default' => '',
                'limit' => 45,
                'after' => 'description',
            ])
            ->create();
        $this->table('roles')
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 100,
                'after' => 'id',
            ])
            ->addColumn('created', 'datetime', [
                'null' => true,
                'default' => null,
                'after' => 'name',
            ])
            ->addColumn('modified', 'datetime', [
                'null' => true,
                'default' => null,
                'after' => 'created',
            ])
            ->addColumn('perm_add', 'boolean', [
                'null' => true,
                'default' => null,
                'after' => 'modified',
            ])
            ->addColumn('perm_modify', 'boolean', [
                'null' => true,
                'default' => null,
                'after' => 'perm_add',
            ])
            ->addColumn('perm_modify_org', 'boolean', [
                'null' => true,
                'default' => null,
                'after' => 'perm_modify',
            ])
            ->addColumn('perm_publish', 'boolean', [
                'null' => true,
                'default' => null,
                'after' => 'perm_modify_org',
            ])
            ->addColumn('perm_delegate', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'perm_publish',
            ])
            ->addColumn('perm_sync', 'boolean', [
                'null' => true,
                'default' => null,
                'after' => 'perm_delegate',
            ])
            ->addColumn('perm_admin', 'boolean', [
                'null' => true,
                'default' => null,
                'after' => 'perm_sync',
            ])
            ->addColumn('perm_audit', 'boolean', [
                'null' => true,
                'default' => null,
                'after' => 'perm_admin',
            ])
            ->addColumn('perm_full', 'boolean', [
                'null' => true,
                'default' => null,
                'after' => 'perm_audit',
            ])
            ->addColumn('perm_auth', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'perm_full',
            ])
            ->addColumn('perm_site_admin', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'perm_auth',
            ])
            ->addColumn('perm_regexp_access', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'perm_site_admin',
            ])
            ->addColumn('perm_tagger', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'perm_regexp_access',
            ])
            ->addColumn('perm_template', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'perm_tagger',
            ])
            ->addColumn('perm_sharing_group', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'perm_template',
            ])
            ->addColumn('perm_tag_editor', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'perm_sharing_group',
            ])
            ->addColumn('perm_sighting', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'perm_tag_editor',
            ])
            ->addColumn('perm_object_template', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'perm_sighting',
            ])
            ->addColumn('default_role', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'perm_object_template',
            ])
            ->addColumn('memory_limit', 'string', [
                'null' => true,
                'default' => '',
                'limit' => 255,
                'after' => 'default_role',
            ])
            ->addColumn('max_execution_time', 'string', [
                'null' => true,
                'default' => '',
                'limit' => 255,
                'after' => 'memory_limit',
            ])
            ->addColumn('restricted_to_site_admin', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'max_execution_time',
            ])
            ->addColumn('perm_publish_zmq', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'restricted_to_site_admin',
            ])
            ->addColumn('perm_publish_kafka', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'perm_publish_zmq',
            ])
            ->addColumn('perm_decaying', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'perm_publish_kafka',
            ])
            ->addColumn('enforce_rate_limit', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'perm_decaying',
            ])
            ->addColumn('rate_limit_count', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'enforce_rate_limit',
            ])
            ->addColumn('perm_galaxy_editor', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'rate_limit_count',
            ])
            ->addColumn('perm_warninglist', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'perm_galaxy_editor',
            ])
            ->addColumn('perm_view_feed_correlations', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'perm_warninglist',
            ])
            ->addColumn('perm_analyst_data', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'perm_view_feed_correlations',
            ])
            ->addColumn('perm_skip_otp', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'perm_analyst_data',
            ])
            ->create();
        $this->table('organisations')
            ->addColumn('name', 'string', [
                'null' => false,
                'default' => '',
                'limit' => 255,
                'after' => 'id',
            ])
            ->addColumn('date_created', 'datetime', [
                'null' => false,
                'after' => 'name',
            ])
            ->addColumn('date_modified', 'datetime', [
                'null' => false,
                'after' => 'date_created',
            ])
            ->addColumn('description', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'date_modified',
            ])
            ->addColumn('type', 'string', [
                'null' => false,
                'default' => '',
                'limit' => 255,
                'after' => 'description',
            ])
            ->addColumn('nationality', 'string', [
                'null' => false,
                'default' => '',
                'limit' => 255,
                'after' => 'type',
            ])
            ->addColumn('sector', 'string', [
                'null' => false,
                'default' => '',
                'limit' => 255,
                'after' => 'nationality',
            ])
            ->addColumn('created_by', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'sector',
            ])
            ->addColumn('uuid', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 40,
                'after' => 'created_by',
            ])
            ->addColumn('contacts', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'uuid',
            ])
            ->addColumn('local', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'contacts',
            ])
            ->addColumn('restricted_to_domain', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'local',
            ])
            ->addColumn('landingpage', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'restricted_to_domain',
            ])
            ->addIndex(['name'], [
                'name' => 'organisations_name',
                'unique' => true,
            ])
            ->addIndex(['uuid'], [
                'name' => 'organisations_uuid',
                'unique' => true,
            ])
            ->create();
        $this->table('regexp')
            ->addColumn('regexp', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'id',
            ])
            ->addColumn('replacement', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'regexp',
            ])
            ->addColumn('type', 'string', [
                'null' => false,
                'default' => 'ALL',
                'limit' => 100,
                'after' => 'replacement',
            ])
            ->create();
        $this->table('galaxy_elements')
            ->addColumn('galaxy_cluster_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('key', 'string', [
                'null' => false,
                'default' => '',
                'limit' => 255,
                'after' => 'galaxy_cluster_id',
            ])
            ->addColumn('value', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'key',
            ])
            ->addIndex(['key'], [
                'name' => 'galaxy_elements_key',
                'unique' => false,
            ])
            ->addIndex(['value'], [
                'name' => 'galaxy_elements_value',
                'unique' => false,
                'limit' => [
                    'value' => 255,
                ],
            ])
            ->addIndex(['galaxy_cluster_id'], [
                'name' => 'galaxy_elements_galaxy_cluster_id',
                'unique' => false,
            ])
            ->create();
        $this->table('sharing_groups')
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'id',
            ])
            ->addColumn('releasability', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'name',
            ])
            ->addColumn('description', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'releasability',
            ])
            ->addColumn('uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'description',
            ])
            ->addColumn('organisation_uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'uuid',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'after' => 'organisation_uuid',
            ])
            ->addColumn('sync_user_id', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'org_id',
            ])
            ->addColumn('active', 'boolean', [
                'null' => false,
                'after' => 'sync_user_id',
            ])
            ->addColumn('created', 'datetime', [
                'null' => false,
                'after' => 'active',
            ])
            ->addColumn('modified', 'datetime', [
                'null' => false,
                'after' => 'created',
            ])
            ->addColumn('local', 'boolean', [
                'null' => false,
                'after' => 'modified',
            ])
            ->addColumn('roaming', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'local',
            ])
            ->addIndex(['uuid'], [
                'name' => 'sharing_groups_uuid',
                'unique' => true,
            ])
            ->addIndex(['name'], [
                'name' => 'sharing_groups_name',
                'unique' => true,
            ])
            ->addIndex(['org_id'], [
                'name' => 'sharing_groups_org_id',
                'unique' => false,
            ])
            ->addIndex(['sync_user_id'], [
                'name' => 'sharing_groups_sync_user_id',
                'unique' => false,
            ])
            ->addIndex(['organisation_uuid'], [
                'name' => 'sharing_groups_organisation_uuid',
                'unique' => false,
            ])
            ->create();
        $this->table('servers')
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'id',
            ])
            ->addColumn('url', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'name',
            ])
            ->addColumn('authkey', 'binary', [
                'null' => false,
                'limit' => 255,
                'after' => 'url',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'after' => 'authkey',
            ])
            ->addColumn('push', 'boolean', [
                'null' => false,
                'after' => 'org_id',
            ])
            ->addColumn('pull', 'boolean', [
                'null' => false,
                'after' => 'push',
            ])
            ->addColumn('push_sightings', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'pull',
            ])
            ->addColumn('push_galaxy_clusters', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'push_sightings',
            ])
            ->addColumn('push_analyst_data', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'push_galaxy_clusters',
            ])
            ->addColumn('pull_analyst_data', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'push_analyst_data',
            ])
            ->addColumn('pull_galaxy_clusters', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'pull_analyst_data',
            ])
            ->addColumn('lastpulledid', 'integer', [
                'null' => true,
                'default' => null,
                'after' => 'pull_galaxy_clusters',
            ])
            ->addColumn('lastpushedid', 'integer', [
                'null' => true,
                'default' => null,
                'after' => 'lastpulledid',
            ])
            ->addColumn('organization', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 10,
                'after' => 'lastpushedid',
            ])
            ->addColumn('remote_org_id', 'integer', [
                'null' => false,
                'after' => 'organization',
            ])
            ->addColumn('publish_without_email', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'remote_org_id',
            ])
            ->addColumn('unpublish_event', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'publish_without_email',
            ])
            ->addColumn('self_signed', 'boolean', [
                'null' => false,
                'after' => 'unpublish_event',
            ])
            ->addColumn('pull_rules', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'self_signed',
            ])
            ->addColumn('push_rules', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'pull_rules',
            ])
            ->addColumn('cert_file', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'push_rules',
            ])
            ->addColumn('client_cert_file', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'cert_file',
            ])
            ->addColumn('internal', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'client_cert_file',
            ])
            ->addColumn('skip_proxy', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'internal',
            ])
            ->addColumn('remove_missing_tags', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'skip_proxy',
            ])
            ->addColumn('caching_enabled', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'remove_missing_tags',
            ])
            ->addColumn('priority', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'caching_enabled',
            ])
            ->addIndex(['org_id'], [
                'name' => 'servers_org_id',
                'unique' => false,
            ])
            ->addIndex(['priority'], [
                'name' => 'servers_priority',
                'unique' => false,
            ])
            ->addIndex(['remote_org_id'], [
                'name' => 'servers_remote_org_id',
                'unique' => false,
            ])
            ->create();
        $this->table('bruteforces')
            ->addColumn('ip', 'string', [
                'null' => false,
                'limit' => 255,
            ])
            ->addColumn('username', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'ip',
            ])
            ->addColumn('expire', 'datetime', [
                'null' => false,
                'after' => 'username',
            ])
            ->create();
        $this->table('event_blocklists')
            ->addColumn('event_uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('created', 'datetime', [
                'null' => false,
                'after' => 'event_uuid',
            ])
            ->addColumn('event_info', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'created',
            ])
            ->addColumn('comment', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'event_info',
            ])
            ->addColumn('event_orgc', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'comment',
            ])
            ->addIndex(['event_uuid'], [
                'name' => 'event_blocklists_event_uuid',
                'unique' => true,
            ])
            ->addIndex(['event_orgc'], [
                'name' => 'event_blocklists_event_orgc',
                'unique' => false,
            ])
            ->create();
        $this->table('analyst_data_blocklists')
            ->addColumn('analyst_data_uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('created', 'datetime', [
                'null' => false,
                'after' => 'analyst_data_uuid',
            ])
            ->addColumn('analyst_data_info', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'created',
            ])
            ->addColumn('comment', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'analyst_data_info',
            ])
            ->addColumn('analyst_data_orgc', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'comment',
            ])
            ->addIndex(['analyst_data_uuid'], [
                'name' => 'analyst_data_blocklists_analyst_data_uuid',
                'unique' => false,
            ])
            ->addIndex(['analyst_data_orgc'], [
                'name' => 'analyst_data_blocklists_analyst_data_orgc',
                'unique' => false,
            ])
            ->create();
        $this->table('users')
            ->addColumn('password', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'id',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'after' => 'password',
            ])
            ->addColumn('server_id', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'org_id',
            ])
            ->addColumn('email', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'server_id',
            ])
            ->addColumn('autoalert', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'email',
            ])
            ->addColumn('authkey', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 40,
                'after' => 'autoalert',
            ])
            ->addColumn('invited_by', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'authkey',
            ])
            ->addColumn('gpgkey', 'text', [
                'null' => true,
                'default' => null,
                'after' => 'invited_by',
            ])
            ->addColumn('certif_public', 'text', [
                'null' => true,
                'default' => null,
                'after' => 'gpgkey',
            ])
            ->addColumn('nids_sid', 'integer', [
                'null' => false,
                'default' => 0,
                'limit' => 15,
                'after' => 'certif_public',
            ])
            ->addColumn('termsaccepted', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'nids_sid',
            ])
            ->addColumn('newsread', 'integer', [
                'null' => true,
                'default' => 0,
                'signed' => false,
                'after' => 'termsaccepted',
            ])
            ->addColumn('role_id', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'newsread',
            ])
            ->addColumn('change_pw', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'role_id',
            ])
            ->addColumn('contactalert', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'change_pw',
            ])
            ->addColumn('disabled', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'contactalert',
            ])
            ->addColumn('expiration', 'datetime', [
                'null' => true,
                'default' => null,
                'after' => 'disabled',
            ])
            ->addColumn('current_login', 'integer', [
                'null' => true,
                'default' => 0,
                'after' => 'expiration',
            ])
            ->addColumn('last_login', 'integer', [
                'null' => true,
                'default' => 0,
                'after' => 'current_login',
            ])
            ->addColumn('force_logout', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'last_login',
            ])
            ->addColumn('date_created', 'biginteger', [
                'null' => true,
                'default' => null,
                'after' => 'force_logout',
            ])
            ->addColumn('date_modified', 'biginteger', [
                'null' => true,
                'default' => null,
                'after' => 'date_created',
            ])
            ->addColumn('sub', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'date_modified',
            ])
            ->addColumn('external_auth_required', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'sub',
            ])
            ->addColumn('external_auth_key', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'external_auth_required',
            ])
            ->addColumn('last_api_access', 'integer', [
                'null' => true,
                'default' => 0,
                'after' => 'external_auth_key',
            ])
            ->addColumn('notification_daily', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'last_api_access',
            ])
            ->addColumn('notification_weekly', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'notification_daily',
            ])
            ->addColumn('notification_monthly', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'notification_weekly',
            ])
            ->addColumn('totp', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'notification_monthly',
            ])
            ->addColumn('hotp_counter', 'integer', [
                'null' => true,
                'default' => null,
                'after' => 'totp',
            ])
            ->addColumn('last_pw_change', 'biginteger', [
                'null' => true,
                'default' => null,
                'after' => 'hotp_counter',
            ])
            ->addIndex(['email'], [
                'name' => 'users_email',
                'unique' => true,
            ])
            ->addIndex(['sub'], [
                'name' => 'users_sub',
                'unique' => true,
            ])
            ->addIndex(['org_id'], [
                'name' => 'users_org_id',
                'unique' => false,
            ])
            ->addIndex(['server_id'], [
                'name' => 'users_server_id',
                'unique' => false,
            ])
            ->create();
        $this->table('notification_logs')
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('type', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'org_id',
            ])
            ->addColumn('timestamp', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'type',
            ])
            ->addIndex(['org_id'], [
                'name' => 'notification_logs_org_id',
                'unique' => false,
            ])
            ->addIndex(['type'], [
                'name' => 'notification_logs_type',
                'unique' => false,
            ])
            ->create();
        $this->table('sharing_group_orgs')
            ->addColumn('sharing_group_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'after' => 'sharing_group_id',
            ])
            ->addColumn('extend', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'org_id',
            ])
            ->addIndex(['org_id'], [
                'name' => 'sharing_group_orgs_org_id',
                'unique' => false,
            ])
            ->addIndex(['sharing_group_id'], [
                'name' => 'sharing_group_orgs_sharing_group_id',
                'unique' => false,
            ])
            ->create();
        $this->table('sightings')
            ->addColumn('attribute_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('event_id', 'integer', [
                'null' => false,
                'after' => 'attribute_id',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'after' => 'event_id',
            ])
            ->addColumn('date_sighting', 'biginteger', [
                'null' => false,
                'after' => 'org_id',
            ])
            ->addColumn('uuid', 'string', [
                'null' => true,
                'default' => '',
                'limit' => 255,
                'after' => 'date_sighting',
            ])
            ->addColumn('source', 'string', [
                'null' => true,
                'default' => '',
                'limit' => 255,
                'after' => 'uuid',
            ])
            ->addColumn('type', 'integer', [
                'null' => true,
                'default' => 0,
                'after' => 'source',
            ])
            ->addIndex(['uuid'], [
                'name' => 'sightings_uuid',
                'unique' => true,
            ])
            ->addIndex(['attribute_id'], [
                'name' => 'sightings_attribute_id',
                'unique' => false,
            ])
            ->addIndex(['event_id'], [
                'name' => 'sightings_event_id',
                'unique' => false,
            ])
            ->addIndex(['org_id'], [
                'name' => 'sightings_org_id',
                'unique' => false,
            ])
            ->addIndex(['source'], [
                'name' => 'sightings_source',
                'unique' => false,
            ])
            ->addIndex(['type'], [
                'name' => 'sightings_type',
                'unique' => false,
            ])
            ->create();
        $this->table('taxonomy_predicates')
            ->addColumn('taxonomy_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('value', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'taxonomy_id',
            ])
            ->addColumn('expanded', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'value',
            ])
            ->addColumn('colour', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 7,
                'after' => 'expanded',
            ])
            ->addColumn('description', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'colour',
            ])
            ->addColumn('exclusive', 'boolean', [
                'null' => true,
                'default' => 0,
                'after' => 'description',
            ])
            ->addColumn('numerical_value', 'integer', [
                'null' => true,
                'default' => null,
                'after' => 'exclusive',
            ])
            ->addIndex(['taxonomy_id'], [
                'name' => 'taxonomy_predicates_taxonomy_id',
                'unique' => false,
            ])
            ->addIndex(['numerical_value'], [
                'name' => 'taxonomy_predicates_numerical_value',
                'unique' => false,
            ])
            ->create();
        $this->table('cake_sessions')
            ->addColumn('data', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'id',
            ])
            ->addColumn('expires', 'integer', [
                'null' => false,
                'after' => 'data',
            ])
            ->addIndex(['expires'], [
                'name' => 'cake_sessions_expires',
                'unique' => false,
            ])
            ->create();
        $this->table('events')
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('date', 'date', [
                'null' => false,
                'after' => 'org_id',
            ])
            ->addColumn('info', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'date',
            ])
            ->addColumn('user_id', 'integer', [
                'null' => false,
                'after' => 'info',
            ])
            ->addColumn('uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'user_id',
            ])
            ->addColumn('published', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'uuid',
            ])
            ->addColumn('analysis', 'integer', [
                'null' => false,
                'after' => 'published',
            ])
            ->addColumn('attribute_count', 'integer', [
                'null' => true,
                'default' => 0,
                'signed' => false,
                'after' => 'analysis',
            ])
            ->addColumn('orgc_id', 'integer', [
                'null' => false,
                'after' => 'attribute_count',
            ])
            ->addColumn('timestamp', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'orgc_id',
            ])
            ->addColumn('distribution', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'timestamp',
            ])
            ->addColumn('sharing_group_id', 'integer', [
                'null' => false,
                'after' => 'distribution',
            ])
            ->addColumn('proposal_email_lock', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'sharing_group_id',
            ])
            ->addColumn('locked', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'proposal_email_lock',
            ])
            ->addColumn('threat_level_id', 'integer', [
                'null' => false,
                'after' => 'locked',
            ])
            ->addColumn('publish_timestamp', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'threat_level_id',
            ])
            ->addColumn('sighting_timestamp', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'publish_timestamp',
            ])
            ->addColumn('disable_correlation', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'sighting_timestamp',
            ])
            ->addColumn('extends_uuid', 'string', [
                'null' => true,
                'default' => '',
                'limit' => 40,
                'after' => 'disable_correlation',
            ])
            ->addColumn('protected', 'boolean', [
                'null' => true,
                'default' => null,
                'after' => 'extends_uuid',
            ])
            ->addIndex(['uuid'], [
                'name' => 'events_uuid',
                'unique' => true,
            ])
            ->addIndex(['info'], [
                'name' => 'events_info',
                'unique' => false,
                'limit' => [
                    'info' => 255,
                ],
            ])
            ->addIndex(['sharing_group_id'], [
                'name' => 'events_sharing_group_id',
                'unique' => false,
            ])
            ->addIndex(['org_id'], [
                'name' => 'events_org_id',
                'unique' => false,
            ])
            ->addIndex(['orgc_id'], [
                'name' => 'events_orgc_id',
                'unique' => false,
            ])
            ->addIndex(['extends_uuid'], [
                'name' => 'events_extends_uuid',
                'unique' => false,
            ])
            ->create();
        $this->table('attributes')
            ->addColumn('event_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('object_id', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'event_id',
            ])
            ->addColumn('object_relation', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'object_id',
            ])
            ->addColumn('category', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'object_relation',
            ])
            ->addColumn('type', 'string', [
                'null' => false,
                'limit' => 100,
                'after' => 'category',
            ])
            ->addColumn('value1', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'type',
            ])
            ->addColumn('value2', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'value1',
            ])
            ->addColumn('to_ids', 'boolean', [
                'null' => false,
                'default' => '1',
                'after' => 'value2',
            ])
            ->addColumn('uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'to_ids',
            ])
            ->addColumn('timestamp', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'uuid',
            ])
            ->addColumn('distribution', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'timestamp',
            ])
            ->addColumn('sharing_group_id', 'integer', [
                'null' => false,
                'after' => 'distribution',
            ])
            ->addColumn('comment', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'sharing_group_id',
            ])
            ->addColumn('deleted', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'comment',
            ])
            ->addColumn('disable_correlation', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'deleted',
            ])
            ->addColumn('first_seen', 'biginteger', [
                'null' => true,
                'default' => null,
                'after' => 'disable_correlation',
            ])
            ->addColumn('last_seen', 'biginteger', [
                'null' => true,
                'default' => null,
                'after' => 'first_seen',
            ])
            ->addIndex(['uuid'], [
                'name' => 'attributes_uuid',
                'unique' => true,
            ])
            ->addIndex(['event_id'], [
                'name' => 'attributes_event_id',
                'unique' => false,
            ])
            ->addIndex(['object_id'], [
                'name' => 'attributes_object_id',
                'unique' => false,
            ])
            ->addIndex(['object_relation'], [
                'name' => 'attributes_object_relation',
                'unique' => false,
            ])
            ->addIndex(['value1'], [
                'name' => 'attributes_value1',
                'unique' => false,
                'limit' => [
                    'value1' => 255,
                ],
            ])
            ->addIndex(['value2'], [
                'name' => 'attributes_value2',
                'unique' => false,
                'limit' => [
                    'value2' => 255,
                ],
            ])
            ->addIndex(['type'], [
                'name' => 'attributes_type',
                'unique' => false,
            ])
            ->addIndex(['category'], [
                'name' => 'attributes_category',
                'unique' => false,
            ])
            ->addIndex(['sharing_group_id'], [
                'name' => 'attributes_sharing_group_id',
                'unique' => false,
            ])
            ->addIndex(['first_seen'], [
                'name' => 'attributes_first_seen',
                'unique' => false,
            ])
            ->addIndex(['last_seen'], [
                'name' => 'attributes_last_seen',
                'unique' => false,
            ])
            ->addIndex(['timestamp'], [
                'name' => 'attributes_timestamp',
                'unique' => false,
            ])
            ->create();
        $this->table('sightingdbs')
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'id',
            ])
            ->addColumn('description', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'name',
            ])
            ->addColumn('owner', 'string', [
                'null' => true,
                'default' => '',
                'limit' => 255,
                'after' => 'description',
            ])
            ->addColumn('host', 'string', [
                'null' => true,
                'default' => 'http://localhost',
                'limit' => 255,
                'after' => 'owner',
            ])
            ->addColumn('port', 'integer', [
                'null' => true,
                'default' => '9999',
                'after' => 'host',
            ])
            ->addColumn('timestamp', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'port',
            ])
            ->addColumn('enabled', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'timestamp',
            ])
            ->addColumn('skip_proxy', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'enabled',
            ])
            ->addColumn('ssl_skip_verification', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'skip_proxy',
            ])
            ->addColumn('namespace', 'string', [
                'null' => true,
                'default' => '',
                'limit' => 255,
                'after' => 'ssl_skip_verification',
            ])
            ->addIndex(['name'], [
                'name' => 'sightingdbs_name',
                'unique' => false,
            ])
            ->addIndex(['owner'], [
                'name' => 'sightingdbs_owner',
                'unique' => false,
            ])
            ->addIndex(['host'], [
                'name' => 'sightingdbs_host',
                'unique' => false,
            ])
            ->addIndex(['port'], [
                'name' => 'sightingdbs_port',
                'unique' => false,
            ])
            ->create();
        $this->table('sightingdb_orgs')
            ->addColumn('sightingdb_id', 'integer', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'after' => 'sightingdb_id',
            ])
            ->addIndex(['sightingdb_id'], [
                'name' => 'sightingdb_orgs_sightingdb_id',
                'unique' => false,
            ])
            ->addIndex(['org_id'], [
                'name' => 'sightingdb_orgs_org_id',
                'unique' => false,
            ])
            ->create();
        $this->table('no_acl_correlations')
            ->addColumn('attribute_id', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => 'id',
            ])
            ->addColumn('1_attribute_id', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => 'attribute_id',
            ])
            ->addColumn('event_id', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => '1_attribute_id',
            ])
            ->addColumn('1_event_id', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => 'event_id',
            ])
            ->addColumn('value_id', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => '1_event_id',
            ])
            ->addIndex(['attribute_id', '1_attribute_id', 'value_id'], [
                'name' => 'no_acl_correlations_unique_correlation',
                'unique' => true,
            ])
            ->addIndex(['event_id'], [
                'name' => 'no_acl_correlations_event_id',
                'unique' => false,
            ])
            ->addIndex(['1_event_id'], [
                'name' => 'no_acl_correlations_1_event_id',
                'unique' => false,
            ])
            ->addIndex(['attribute_id'], [
                'name' => 'no_acl_correlations_attribute_id',
                'unique' => false,
            ])
            ->addIndex(['1_attribute_id'], [
                'name' => 'no_acl_correlations_1_attribute_id',
                'unique' => false,
            ])
            ->addIndex(['value_id'], [
                'name' => 'no_acl_correlations_value_id',
                'unique' => false,
            ])
            ->create();
        $this->table('event_reports')
            ->addColumn('uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('event_id', 'integer', [
                'null' => false,
                'after' => 'uuid',
            ])
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'event_id',
            ])
            ->addColumn('content', 'text', [
                'null' => true,
                'default' => null,
                'after' => 'name',
            ])
            ->addColumn('distribution', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'content',
            ])
            ->addColumn('sharing_group_id', 'integer', [
                'null' => true,
                'default' => null,
                'after' => 'distribution',
            ])
            ->addColumn('timestamp', 'integer', [
                'null' => false,
                'after' => 'sharing_group_id',
            ])
            ->addColumn('deleted', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'timestamp',
            ])
            ->addIndex(['uuid'], [
                'name' => 'event_reports_u_uuid',
                'unique' => true,
            ])
            ->addIndex(['name'], [
                'name' => 'event_reports_name',
                'unique' => false,
            ])
            ->addIndex(['event_id'], [
                'name' => 'event_reports_event_id',
                'unique' => false,
            ])
            ->create();
        $this->table('attachment_scans')
            ->addColumn('type', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('attribute_id', 'integer', [
                'null' => false,
                'after' => 'type',
            ])
            ->addColumn('infected', 'boolean', [
                'null' => false,
                'after' => 'attribute_id',
            ])
            ->addColumn('malware_name', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 191,
                'after' => 'infected',
            ])
            ->addColumn('timestamp', 'integer', [
                'null' => false,
                'after' => 'malware_name',
            ])
            ->addIndex(['type', 'attribute_id'], [
                'name' => 'attachment_scans_index',
                'unique' => false,
            ])
            ->create();
        $this->table('default_correlations')
            ->addColumn('attribute_id', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => 'id',
            ])
            ->addColumn('object_id', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => 'attribute_id',
            ])
            ->addColumn('event_id', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => 'object_id',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => 'event_id',
            ])
            ->addColumn('distribution', 'integer', [
                'null' => false,
                'after' => 'org_id',
            ])
            ->addColumn('object_distribution', 'integer', [
                'null' => false,
                'after' => 'distribution',
            ])
            ->addColumn('event_distribution', 'integer', [
                'null' => false,
                'after' => 'object_distribution',
            ])
            ->addColumn('sharing_group_id', 'integer', [
                'null' => false,
                'default' => 0,
                'limit' => 10,
                'signed' => false,
                'after' => 'event_distribution',
            ])
            ->addColumn('object_sharing_group_id', 'integer', [
                'null' => false,
                'default' => 0,
                'limit' => 10,
                'signed' => false,
                'after' => 'sharing_group_id',
            ])
            ->addColumn('event_sharing_group_id', 'integer', [
                'null' => false,
                'default' => 0,
                'limit' => 10,
                'signed' => false,
                'after' => 'object_sharing_group_id',
            ])
            ->addColumn('1_attribute_id', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => 'event_sharing_group_id',
            ])
            ->addColumn('1_object_id', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => '1_attribute_id',
            ])
            ->addColumn('1_event_id', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => '1_object_id',
            ])
            ->addColumn('1_org_id', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => '1_event_id',
            ])
            ->addColumn('1_distribution', 'integer', [
                'null' => false,
                'after' => '1_org_id',
            ])
            ->addColumn('1_object_distribution', 'integer', [
                'null' => false,
                'after' => '1_distribution',
            ])
            ->addColumn('1_event_distribution', 'integer', [
                'null' => false,
                'after' => '1_object_distribution',
            ])
            ->addColumn('1_sharing_group_id', 'integer', [
                'null' => false,
                'default' => 0,
                'limit' => 10,
                'signed' => false,
                'after' => '1_event_distribution',
            ])
            ->addColumn('1_object_sharing_group_id', 'integer', [
                'null' => false,
                'default' => 0,
                'limit' => 10,
                'signed' => false,
                'after' => '1_sharing_group_id',
            ])
            ->addColumn('1_event_sharing_group_id', 'integer', [
                'null' => false,
                'default' => 0,
                'limit' => 10,
                'signed' => false,
                'after' => '1_object_sharing_group_id',
            ])
            ->addColumn('value_id', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => '1_event_sharing_group_id',
            ])
            ->addIndex(['attribute_id', '1_attribute_id', 'value_id'], [
                'name' => 'default_correlations_unique_correlation',
                'unique' => true,
            ])
            ->addIndex(['event_id'], [
                'name' => 'default_correlations_event_id',
                'unique' => false,
            ])
            ->addIndex(['attribute_id'], [
                'name' => 'default_correlations_attribute_id',
                'unique' => false,
            ])
            ->addIndex(['object_id'], [
                'name' => 'default_correlations_object_id',
                'unique' => false,
            ])
            ->addIndex(['1_event_id'], [
                'name' => 'default_correlations_1_event_id',
                'unique' => false,
            ])
            ->addIndex(['1_attribute_id'], [
                'name' => 'default_correlations_1_attribute_id',
                'unique' => false,
            ])
            ->addIndex(['1_object_id'], [
                'name' => 'default_correlations_1_object_id',
                'unique' => false,
            ])
            ->addIndex(['value_id'], [
                'name' => 'default_correlations_value_id',
                'unique' => false,
            ])
            ->create();
        $this->table('inbox')
            ->addColumn('uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('title', 'string', [
                'null' => false,
                'limit' => 191,
                'after' => 'uuid',
            ])
            ->addColumn('type', 'string', [
                'null' => false,
                'limit' => 191,
                'after' => 'title',
            ])
            ->addColumn('ip', 'string', [
                'null' => false,
                'limit' => 191,
                'after' => 'type',
            ])
            ->addColumn('user_agent', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'ip',
            ])
            ->addColumn('user_agent_sha256', 'string', [
                'null' => false,
                'limit' => 64,
                'after' => 'user_agent',
            ])
            ->addColumn('comment', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'user_agent_sha256',
            ])
            ->addColumn('deleted', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'comment',
            ])
            ->addColumn('timestamp', 'integer', [
                'null' => false,
                'after' => 'deleted',
            ])
            ->addColumn('store_as_file', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'timestamp',
            ])
            ->addColumn('data', 'text', [
                'null' => true,
                'default' => null,
                'after' => 'store_as_file',
            ])
            ->addIndex(['uuid'], [
                'name' => 'inbox_uuid',
                'unique' => true,
            ])
            ->addIndex(['title'], [
                'name' => 'inbox_title',
                'unique' => false,
            ])
            ->addIndex(['type'], [
                'name' => 'inbox_type',
                'unique' => false,
            ])
            ->addIndex(['user_agent_sha256'], [
                'name' => 'inbox_user_agent_sha256',
                'unique' => false,
            ])
            ->addIndex(['ip'], [
                'name' => 'inbox_ip',
                'unique' => false,
            ])
            ->addIndex(['timestamp'], [
                'name' => 'inbox_timestamp',
                'unique' => false,
            ])
            ->create();
        $this->table('dashboards')
            ->addColumn('uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 191,
                'after' => 'uuid',
            ])
            ->addColumn('description', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'name',
            ])
            ->addColumn('default', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'description',
            ])
            ->addColumn('selectable', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'default',
            ])
            ->addColumn('user_id', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'selectable',
            ])
            ->addColumn('restrict_to_org_id', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'user_id',
            ])
            ->addColumn('restrict_to_role_id', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'restrict_to_org_id',
            ])
            ->addColumn('restrict_to_permission_flag', 'string', [
                'null' => false,
                'default' => '',
                'limit' => 191,
                'after' => 'restrict_to_role_id',
            ])
            ->addColumn('value', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'restrict_to_permission_flag',
            ])
            ->addColumn('timestamp', 'integer', [
                'null' => false,
                'after' => 'value',
            ])
            ->addIndex(['uuid'], [
                'name' => 'dashboards_uuid',
                'unique' => true,
            ])
            ->addIndex(['name'], [
                'name' => 'dashboards_name',
                'unique' => false,
            ])
            ->addIndex(['user_id'], [
                'name' => 'dashboards_user_id',
                'unique' => false,
            ])
            ->addIndex(['restrict_to_org_id'], [
                'name' => 'dashboards_restrict_to_org_id',
                'unique' => false,
            ])
            ->addIndex(['restrict_to_permission_flag'], [
                'name' => 'dashboards_restrict_to_permission_flag',
                'unique' => false,
            ])
            ->create();
        $this->table('collection_elements')
            ->addColumn('uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('element_uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'uuid',
            ])
            ->addColumn('element_type', 'string', [
                'null' => false,
                'limit' => 80,
                'after' => 'element_uuid',
            ])
            ->addColumn('collection_id', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => 'element_type',
            ])
            ->addColumn('description', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'collection_id',
            ])
            ->addIndex(['uuid'], [
                'name' => 'collection_elements_uuid',
                'unique' => true,
            ])
            ->addIndex(['element_uuid', 'collection_id'], [
                'name' => 'collection_elements_unique_element',
                'unique' => true,
            ])
            ->addIndex(['element_uuid'], [
                'name' => 'collection_elements_element_uuid',
                'unique' => false,
            ])
            ->addIndex(['element_type'], [
                'name' => 'collection_elements_element_type',
                'unique' => false,
            ])
            ->addIndex(['collection_id'], [
                'name' => 'collection_elements_collection_id',
                'unique' => false,
            ])
            ->create();
        $this->table('auth_keys')
            ->addColumn('uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('authkey', 'string', [
                'null' => false,
                'limit' => 72,
                'after' => 'uuid',
            ])
            ->addColumn('authkey_start', 'string', [
                'null' => false,
                'limit' => 4,
                'after' => 'authkey',
            ])
            ->addColumn('authkey_end', 'string', [
                'null' => false,
                'limit' => 4,
                'after' => 'authkey_start',
            ])
            ->addColumn('created', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => 'authkey_end',
            ])
            ->addColumn('expiration', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => 'created',
            ])
            ->addColumn('read_only', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'expiration',
            ])
            ->addColumn('user_id', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => 'read_only',
            ])
            ->addColumn('comment', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'user_id',
            ])
            ->addColumn('allowed_ips', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'comment',
            ])
            ->addColumn('unique_ips', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'allowed_ips',
            ])
            ->addIndex(['authkey_start'], [
                'name' => 'auth_keys_authkey_start',
                'unique' => false,
            ])
            ->addIndex(['authkey_end'], [
                'name' => 'auth_keys_authkey_end',
                'unique' => false,
            ])
            ->addIndex(['created'], [
                'name' => 'auth_keys_created',
                'unique' => false,
            ])
            ->addIndex(['expiration'], [
                'name' => 'auth_keys_expiration',
                'unique' => false,
            ])
            ->addIndex(['user_id'], [
                'name' => 'auth_keys_user_id',
                'unique' => false,
            ])
            ->create();
        $this->table('notes')
            ->addColumn('uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('object_uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'uuid',
            ])
            ->addColumn('object_type', 'string', [
                'null' => false,
                'limit' => 80,
                'after' => 'object_uuid',
            ])
            ->addColumn('authors', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'object_type',
            ])
            ->addColumn('org_uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'authors',
            ])
            ->addColumn('orgc_uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'org_uuid',
            ])
            ->addColumn('created', 'datetime', [
                'null' => false,
                'after' => 'orgc_uuid',
            ])
            ->addColumn('modified', 'datetime', [
                'null' => false,
                'after' => 'created',
            ])
            ->addColumn('distribution', 'integer', [
                'null' => false,
                'after' => 'modified',
            ])
            ->addColumn('sharing_group_id', 'integer', [
                'null' => true,
                'default' => null,
                'limit' => 10,
                'signed' => false,
                'after' => 'distribution',
            ])
            ->addColumn('locked', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'sharing_group_id',
            ])
            ->addColumn('note', 'text', [
                'null' => true,
                'default' => null,
                'after' => 'locked',
            ])
            ->addColumn('language', 'string', [
                'null' => true,
                'default' => 'en',
                'limit' => 16,
                'after' => 'note',
            ])
            ->addIndex(['uuid'], [
                'name' => 'notes_uuid',
                'unique' => true,
            ])
            ->addIndex(['object_uuid'], [
                'name' => 'notes_object_uuid',
                'unique' => false,
            ])
            ->addIndex(['object_type'], [
                'name' => 'notes_object_type',
                'unique' => false,
            ])
            ->addIndex(['org_uuid'], [
                'name' => 'notes_org_uuid',
                'unique' => false,
            ])
            ->addIndex(['orgc_uuid'], [
                'name' => 'notes_orgc_uuid',
                'unique' => false,
            ])
            ->addIndex(['distribution'], [
                'name' => 'notes_distribution',
                'unique' => false,
            ])
            ->addIndex(['sharing_group_id'], [
                'name' => 'notes_sharing_group_id',
                'unique' => false,
            ])
            ->create();
        $this->table('relationships')
            ->addColumn('uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('object_uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'uuid',
            ])
            ->addColumn('object_type', 'string', [
                'null' => false,
                'limit' => 80,
                'after' => 'object_uuid',
            ])
            ->addColumn('authors', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'object_type',
            ])
            ->addColumn('org_uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'authors',
            ])
            ->addColumn('orgc_uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'org_uuid',
            ])
            ->addColumn('created', 'datetime', [
                'null' => false,
                'after' => 'orgc_uuid',
            ])
            ->addColumn('modified', 'datetime', [
                'null' => false,
                'after' => 'created',
            ])
            ->addColumn('distribution', 'integer', [
                'null' => false,
                'after' => 'modified',
            ])
            ->addColumn('sharing_group_id', 'integer', [
                'null' => true,
                'default' => null,
                'limit' => 10,
                'signed' => false,
                'after' => 'distribution',
            ])
            ->addColumn('locked', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'sharing_group_id',
            ])
            ->addColumn('relationship_type', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'locked',
            ])
            ->addColumn('related_object_uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'relationship_type',
            ])
            ->addColumn('related_object_type', 'string', [
                'null' => false,
                'limit' => 80,
                'after' => 'related_object_uuid',
            ])
            ->addIndex(['uuid'], [
                'name' => 'relationships_uuid',
                'unique' => true,
            ])
            ->addIndex(['object_uuid'], [
                'name' => 'relationships_object_uuid',
                'unique' => false,
            ])
            ->addIndex(['object_type'], [
                'name' => 'relationships_object_type',
                'unique' => false,
            ])
            ->addIndex(['org_uuid'], [
                'name' => 'relationships_org_uuid',
                'unique' => false,
            ])
            ->addIndex(['orgc_uuid'], [
                'name' => 'relationships_orgc_uuid',
                'unique' => false,
            ])
            ->addIndex(['distribution'], [
                'name' => 'relationships_distribution',
                'unique' => false,
            ])
            ->addIndex(['sharing_group_id'], [
                'name' => 'relationships_sharing_group_id',
                'unique' => false,
            ])
            ->addIndex(['relationship_type'], [
                'name' => 'relationships_relationship_type',
                'unique' => false,
            ])
            ->addIndex(['related_object_uuid'], [
                'name' => 'relationships_related_object_uuid',
                'unique' => false,
            ])
            ->addIndex(['related_object_type'], [
                'name' => 'relationships_related_object_type',
                'unique' => false,
            ])
            ->create();
        $this->table('collections')
            ->addColumn('uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => 'uuid',
            ])
            ->addColumn('orgc_id', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => 'org_id',
            ])
            ->addColumn('user_id', 'integer', [
                'null' => false,
                'limit' => 10,
                'signed' => false,
                'after' => 'orgc_id',
            ])
            ->addColumn('created', 'datetime', [
                'null' => false,
                'after' => 'user_id',
            ])
            ->addColumn('modified', 'datetime', [
                'null' => false,
                'after' => 'created',
            ])
            ->addColumn('distribution', 'integer', [
                'null' => false,
                'after' => 'modified',
            ])
            ->addColumn('sharing_group_id', 'integer', [
                'null' => true,
                'default' => null,
                'limit' => 10,
                'signed' => false,
                'after' => 'distribution',
            ])
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 191,
                'after' => 'sharing_group_id',
            ])
            ->addColumn('type', 'string', [
                'null' => false,
                'limit' => 80,
                'after' => 'name',
            ])
            ->addColumn('description', 'text', [
                'null' => true,
                'default' => null,
                'after' => 'type',
            ])
            ->addIndex(['uuid'], [
                'name' => 'collections_uuid',
                'unique' => true,
            ])
            ->addIndex(['name'], [
                'name' => 'collections_name',
                'unique' => false,
            ])
            ->addIndex(['type'], [
                'name' => 'collections_type',
                'unique' => false,
            ])
            ->addIndex(['org_id'], [
                'name' => 'collections_org_id',
                'unique' => false,
            ])
            ->addIndex(['orgc_id'], [
                'name' => 'collections_orgc_id',
                'unique' => false,
            ])
            ->addIndex(['user_id'], [
                'name' => 'collections_user_id',
                'unique' => false,
            ])
            ->addIndex(['distribution'], [
                'name' => 'collections_distribution',
                'unique' => false,
            ])
            ->addIndex(['sharing_group_id'], [
                'name' => 'collections_sharing_group_id',
                'unique' => false,
            ])
            ->create();
        $this->table('user_login_profiles')
            ->addColumn('created_at', 'timestamp', [
                'null' => false,
                'default' => 'CURRENT_TIMESTAMP',
                'after' => 'id',
            ])
            ->addColumn('user_id', 'integer', [
                'null' => false,
                'after' => 'created_at',
            ])
            ->addColumn('status', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 191,
                'after' => 'user_id',
            ])
            ->addColumn('ip', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 191,
                'after' => 'status',
            ])
            ->addColumn('user_agent', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 191,
                'after' => 'ip',
            ])
            ->addColumn('accept_lang', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 191,
                'after' => 'user_agent',
            ])
            ->addColumn('geoip', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 191,
                'after' => 'accept_lang',
            ])
            ->addColumn('ua_platform', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 191,
                'after' => 'geoip',
            ])
            ->addColumn('ua_browser', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 191,
                'after' => 'ua_platform',
            ])
            ->addColumn('ua_pattern', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 191,
                'after' => 'ua_browser',
            ])
            ->addColumn('hash', 'string', [
                'null' => false,
                'limit' => 32,
                'after' => 'ua_pattern',
            ])
            ->addIndex(['hash'], [
                'name' => 'user_login_profiles_hash',
                'unique' => true,
            ])
            ->addIndex(['ip'], [
                'name' => 'user_login_profiles_ip',
                'unique' => false,
            ])
            ->addIndex(['status'], [
                'name' => 'user_login_profiles_status',
                'unique' => false,
            ])
            ->addIndex(['geoip'], [
                'name' => 'user_login_profiles_geoip',
                'unique' => false,
            ])
            ->addIndex(['user_id'], [
                'name' => 'user_login_profiles_user_id',
                'unique' => false,
            ])
            ->create();
        $this->table('cryptographic_keys')
            ->addColumn('uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('type', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'uuid',
            ])
            ->addColumn('timestamp', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'type',
            ])
            ->addColumn('parent_id', 'integer', [
                'null' => false,
                'after' => 'timestamp',
            ])
            ->addColumn('parent_type', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'parent_id',
            ])
            ->addColumn('key_data', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'parent_type',
            ])
            ->addColumn('revoked', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'key_data',
            ])
            ->addColumn('fingerprint', 'string', [
                'null' => false,
                'default' => '',
                'limit' => 255,
                'after' => 'revoked',
            ])
            ->addIndex(['uuid'], [
                'name' => 'cryptographic_keys_uuid',
                'unique' => false,
            ])
            ->addIndex(['type'], [
                'name' => 'cryptographic_keys_type',
                'unique' => false,
            ])
            ->addIndex(['parent_id'], [
                'name' => 'cryptographic_keys_parent_id',
                'unique' => false,
            ])
            ->addIndex(['parent_type'], [
                'name' => 'cryptographic_keys_parent_type',
                'unique' => false,
            ])
            ->addIndex(['fingerprint'], [
                'name' => 'cryptographic_keys_fingerprint',
                'unique' => false,
            ])
            ->create();
        $this->table('system_settings')
            ->addColumn('setting', 'string', [
                'null' => false,
                'limit' => 255,
            ])
            ->addColumn('value', 'binary', [
                'null' => false,
                'after' => 'setting',
            ])
            ->addIndex(['setting'], [
                'name' => 'system_settings_setting',
                'unique' => true,
            ])
            ->create();
        $this->table('access_logs')
            ->addColumn('created', 'datetime', [
                'null' => false,
                'limit' => 4,
                'after' => 'id',
            ])
            ->addColumn('user_id', 'integer', [
                'null' => false,
                'after' => 'created',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'after' => 'user_id',
            ])
            ->addColumn('authkey_id', 'integer', [
                'null' => true,
                'default' => null,
                'after' => 'org_id',
            ])
            ->addColumn('ip', 'binary', [
                'null' => true,
                'default' => null,
                'limit' => 16,
                'after' => 'authkey_id',
            ])
            ->addColumn('request_method', 'integer', [
                'null' => false,
                'after' => 'ip',
            ])
            ->addColumn('user_agent', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'request_method',
            ])
            ->addColumn('request_id', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'user_agent',
            ])
            ->addColumn('controller', 'string', [
                'null' => false,
                'limit' => 20,
                'after' => 'request_id',
            ])
            ->addColumn('action', 'string', [
                'null' => false,
                'limit' => 191,
                'after' => 'controller',
            ])
            ->addColumn('url', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'action',
            ])
            ->addColumn('request', 'binary', [
                'null' => true,
                'default' => null,
                'after' => 'url',
            ])
            ->addColumn('response_code', 'smallinteger', [
                'null' => false,
                'after' => 'request',
            ])
            ->addColumn('memory_usage', 'integer', [
                'null' => false,
                'after' => 'response_code',
            ])
            ->addColumn('duration', 'integer', [
                'null' => false,
                'after' => 'memory_usage',
            ])
            ->addColumn('query_count', 'integer', [
                'null' => false,
                'after' => 'duration',
            ])
            ->addColumn('query_log', 'binary', [
                'null' => true,
                'default' => null,
                'after' => 'query_count',
            ])
            ->addIndex(['user_id'], [
                'name' => 'access_logs_user_id',
                'unique' => false,
            ])
            ->create();
        $this->table('correlation_exclusions')
            ->addColumn('value', 'text', [
                'null' => false,
                'limit' => 65535,
                'after' => 'id',
            ])
            ->addColumn('from_json', 'boolean', [
                'null' => true,
                'default' => 0,
                'after' => 'value',
            ])
            ->addColumn('comment', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'from_json',
            ])
            ->addIndex(['value'], [
                'name' => 'correlation_exclusions_value',
                'unique' => true,
                'limit' => [
                    'value' => 191,
                ],
            ])
            ->create();
        $this->table('workflows')
            ->addColumn('uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 191,
                'after' => 'uuid',
            ])
            ->addColumn('description', 'string', [
                'null' => false,
                'limit' => 191,
                'after' => 'name',
            ])
            ->addColumn('timestamp', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'description',
            ])
            ->addColumn('enabled', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'timestamp',
            ])
            ->addColumn('counter', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'enabled',
            ])
            ->addColumn('trigger_id', 'string', [
                'null' => false,
                'limit' => 191,
                'after' => 'counter',
            ])
            ->addColumn('debug_enabled', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'trigger_id',
            ])
            ->addColumn('data', 'text', [
                'null' => true,
                'default' => null,
                'after' => 'debug_enabled',
            ])
            ->addIndex(['uuid'], [
                'name' => 'workflows_uuid',
                'unique' => false,
            ])
            ->addIndex(['name'], [
                'name' => 'workflows_name',
                'unique' => false,
            ])
            ->addIndex(['timestamp'], [
                'name' => 'workflows_timestamp',
                'unique' => false,
            ])
            ->addIndex(['trigger_id'], [
                'name' => 'workflows_trigger_id',
                'unique' => false,
            ])
            ->create();
        $this->table('audit_logs')
            ->addColumn('created', 'datetime', [
                'null' => false,
                'after' => 'id',
            ])
            ->addColumn('user_id', 'integer', [
                'null' => false,
                'after' => 'created',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'after' => 'user_id',
            ])
            ->addColumn('authkey_id', 'integer', [
                'null' => true,
                'default' => null,
                'after' => 'org_id',
            ])
            ->addColumn('ip', 'binary', [
                'null' => true,
                'default' => null,
                'limit' => 16,
                'after' => 'authkey_id',
            ])
            ->addColumn('request_type', 'integer', [
                'null' => false,
                'after' => 'ip',
            ])
            ->addColumn('request_id', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'request_type',
            ])
            ->addColumn('action', 'string', [
                'null' => false,
                'limit' => 20,
                'after' => 'request_id',
            ])
            ->addColumn('model', 'string', [
                'null' => false,
                'limit' => 80,
                'after' => 'action',
            ])
            ->addColumn('model_id', 'integer', [
                'null' => false,
                'after' => 'model',
            ])
            ->addColumn('model_title', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'model_id',
            ])
            ->addColumn('event_id', 'integer', [
                'null' => true,
                'default' => null,
                'after' => 'model_title',
            ])
            ->addColumn('change', 'binary', [
                'null' => true,
                'default' => null,
                'after' => 'event_id',
            ])
            ->addIndex(['event_id'], [
                'name' => 'audit_logs_event_id',
                'unique' => false,
            ])
            ->addIndex(['model_id'], [
                'name' => 'audit_logs_model_id',
                'unique' => false,
            ])
            ->create();
        $this->table('over_correlating_values')
            ->addColumn('value', 'string', [
                'null' => false,
                'limit' => 191,
                'after' => 'id',
            ])
            ->addColumn('occurrence', 'integer', [
                'null' => true,
                'default' => null,
                'limit' => 10,
                'signed' => false,
                'after' => 'value',
            ])
            ->addIndex(['value'], [
                'name' => 'over_correlating_values_value',
                'unique' => true,
            ])
            ->addIndex(['occurrence'], [
                'name' => 'over_correlating_values_occurrence',
                'unique' => false,
            ])
            ->create();
        $this->table('sharing_group_blueprints')
            ->addColumn('uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 191,
                'after' => 'uuid',
            ])
            ->addColumn('timestamp', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'name',
            ])
            ->addColumn('user_id', 'integer', [
                'null' => false,
                'after' => 'timestamp',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'after' => 'user_id',
            ])
            ->addColumn('sharing_group_id', 'integer', [
                'null' => true,
                'default' => null,
                'after' => 'org_id',
            ])
            ->addColumn('rules', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'sharing_group_id',
            ])
            ->addIndex(['uuid'], [
                'name' => 'sharing_group_blueprints_uuid',
                'unique' => false,
            ])
            ->addIndex(['name'], [
                'name' => 'sharing_group_blueprints_name',
                'unique' => false,
            ])
            ->addIndex(['org_id'], [
                'name' => 'sharing_group_blueprints_org_id',
                'unique' => false,
            ])
            ->addIndex(['sharing_group_id'], [
                'name' => 'sharing_group_blueprints_sharing_group_id',
                'unique' => false,
            ])
            ->create();
        $this->table('opinions')
            ->addColumn('uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('object_uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'uuid',
            ])
            ->addColumn('object_type', 'string', [
                'null' => false,
                'limit' => 80,
                'after' => 'object_uuid',
            ])
            ->addColumn('authors', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'object_type',
            ])
            ->addColumn('org_uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'authors',
            ])
            ->addColumn('orgc_uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'org_uuid',
            ])
            ->addColumn('created', 'datetime', [
                'null' => false,
                'after' => 'orgc_uuid',
            ])
            ->addColumn('modified', 'datetime', [
                'null' => false,
                'after' => 'created',
            ])
            ->addColumn('distribution', 'integer', [
                'null' => false,
                'after' => 'modified',
            ])
            ->addColumn('sharing_group_id', 'integer', [
                'null' => true,
                'default' => null,
                'limit' => 10,
                'signed' => false,
                'after' => 'distribution',
            ])
            ->addColumn('locked', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'sharing_group_id',
            ])
            ->addColumn('opinion', 'integer', [
                'null' => true,
                'default' => null,
                'limit' => 10,
                'signed' => false,
                'after' => 'locked',
            ])
            ->addColumn('comment', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'opinion',
            ])
            ->addIndex(['uuid'], [
                'name' => 'opinions_uuid',
                'unique' => true,
            ])
            ->addIndex(['object_uuid'], [
                'name' => 'opinions_object_uuid',
                'unique' => false,
            ])
            ->addIndex(['object_type'], [
                'name' => 'opinions_object_type',
                'unique' => false,
            ])
            ->addIndex(['org_uuid'], [
                'name' => 'opinions_org_uuid',
                'unique' => false,
            ])
            ->addIndex(['orgc_uuid'], [
                'name' => 'opinions_orgc_uuid',
                'unique' => false,
            ])
            ->addIndex(['distribution'], [
                'name' => 'opinions_distribution',
                'unique' => false,
            ])
            ->addIndex(['sharing_group_id'], [
                'name' => 'opinions_sharing_group_id',
                'unique' => false,
            ])
            ->addIndex(['opinion'], [
                'name' => 'opinions_opinion',
                'unique' => false,
            ])
            ->create();
        $this->table('cerebrates')
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 191,
                'after' => 'id',
            ])
            ->addColumn('url', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'name',
            ])
            ->addColumn('authkey', 'binary', [
                'null' => false,
                'limit' => 255,
                'after' => 'url',
            ])
            ->addColumn('open', 'boolean', [
                'null' => true,
                'default' => 0,
                'after' => 'authkey',
            ])
            ->addColumn('org_id', 'integer', [
                'null' => false,
                'after' => 'open',
            ])
            ->addColumn('pull_orgs', 'boolean', [
                'null' => true,
                'default' => 0,
                'after' => 'org_id',
            ])
            ->addColumn('pull_sharing_groups', 'boolean', [
                'null' => true,
                'default' => 0,
                'after' => 'pull_orgs',
            ])
            ->addColumn('self_signed', 'boolean', [
                'null' => true,
                'default' => 0,
                'after' => 'pull_sharing_groups',
            ])
            ->addColumn('cert_file', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'self_signed',
            ])
            ->addColumn('client_cert_file', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 255,
                'after' => 'cert_file',
            ])
            ->addColumn('internal', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'client_cert_file',
            ])
            ->addColumn('skip_proxy', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'internal',
            ])
            ->addColumn('description', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'skip_proxy',
            ])
            ->addIndex(['url'], [
                'name' => 'cerebrates_url',
                'unique' => false,
            ])
            ->addIndex(['org_id'], [
                'name' => 'cerebrates_org_id',
                'unique' => false,
            ])
            ->create();
        $this->table('taxii_servers')
            ->addColumn('uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 191,
                'after' => 'uuid',
            ])
            ->addColumn('owner', 'string', [
                'null' => false,
                'limit' => 191,
                'after' => 'name',
            ])
            ->addColumn('baseurl', 'string', [
                'null' => false,
                'limit' => 191,
                'after' => 'owner',
            ])
            ->addColumn('api_root', 'string', [
                'null' => false,
                'default' => 0,
                'limit' => 191,
                'after' => 'baseurl',
            ])
            ->addColumn('description', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'api_root',
            ])
            ->addColumn('filters', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'description',
            ])
            ->addColumn('api_key', 'string', [
                'null' => false,
                'limit' => 255,
                'after' => 'filters',
            ])
            ->addColumn('collection', 'string', [
                'null' => true,
                'default' => null,
                'limit' => 40,
                'after' => 'api_key',
            ])
            ->addIndex(['uuid'], [
                'name' => 'taxii_servers_uuid',
                'unique' => false,
            ])
            ->addIndex(['name'], [
                'name' => 'taxii_servers_name',
                'unique' => false,
            ])
            ->addIndex(['baseurl'], [
                'name' => 'taxii_servers_baseurl',
                'unique' => false,
            ])
            ->create();
        $this->table('correlation_values')
            ->addColumn('value', 'string', [
                'null' => false,
                'limit' => 191,
                'after' => 'id',
            ])
            ->addIndex(['value'], [
                'name' => 'correlation_values_value',
                'unique' => true,
            ])
            ->create();
        $this->table('workflow_blueprints')
            ->addColumn('uuid', 'string', [
                'null' => false,
                'limit' => 40,
                'after' => 'id',
            ])
            ->addColumn('name', 'string', [
                'null' => false,
                'limit' => 191,
                'after' => 'uuid',
            ])
            ->addColumn('description', 'string', [
                'null' => false,
                'limit' => 191,
                'after' => 'name',
            ])
            ->addColumn('timestamp', 'integer', [
                'null' => false,
                'default' => 0,
                'after' => 'description',
            ])
            ->addColumn('default', 'boolean', [
                'null' => false,
                'default' => 0,
                'after' => 'timestamp',
            ])
            ->addColumn('data', 'text', [
                'null' => true,
                'default' => null,
                'limit' => 65535,
                'after' => 'default',
            ])
            ->addIndex(['uuid'], [
                'name' => 'workflow_blueprints_uuid',
                'unique' => false,
            ])
            ->addIndex(['name'], [
                'name' => 'workflow_blueprints_name',
                'unique' => false,
            ])
            ->addIndex(['timestamp'], [
                'name' => 'workflow_blueprints_timestamp',
                'unique' => false,
            ])
            ->create();
    }
}
