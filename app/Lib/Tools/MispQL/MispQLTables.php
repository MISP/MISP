<?php

/**
 * What MispQL knows of each table: its endpoints, where its rows sit, its
 * default columns, how it is counted and the names it can be sorted by.
 *
 * Sort names are read from the model's REST_SEARCH_ORDER_FIELDS: every field
 * of the table's own model sorts under its own name, except those listed in
 * `sortExcept`, and `sortAliases` adds names for fields spelled otherwise in
 * a statement. A sort alias whose target the model does not list is ignored.
 */
class MispQLTables
{
    const TABLES = [
        'attributes' => [
            'rowKey' => 'Attribute',
            'model' => 'MispAttribute',
            'modelAlias' => 'Attribute',
            'sortExcept' => [],
            'sortAliases' => ['publish_timestamp' => 'Event.publish_timestamp'],
            'columns' => ['id', 'event_id', 'category', 'type', 'value', 'to_ids', 'timestamp', 'Tag'],
            'count' => 'body',
            'aliases' => [
                'eventinfo' => 'Event.info',
                'org' => 'Event.Orgc.name',
                'tags' => 'Tag',
                'event_timestamp' => 'Event.timestamp',
                'publish_timestamp' => 'Event.publish_timestamp',
                'threat_level_id' => 'Event.threat_level_id',
            ],
            'metadata' => false,
            'path' => '/attributes/%s',
        ],
        'events' => [
            'rowKey' => 'Event',
            'model' => 'Event',
            'modelAlias' => 'Event',
            'sortExcept' => ['info'],
            'sortAliases' => ['event_id' => 'id', 'eventinfo' => 'info', 'event_timestamp' => 'timestamp'],
            'columns' => [
                'id', 'date', 'info', 'Orgc.name', 'threat_level_id', 'analysis', 'published',
                'attribute_count', 'Tag',
            ],
            'count' => 'header',
            'aliases' => [
                'event_id' => 'id',
                'eventinfo' => 'info',
                'org' => 'Orgc.name',
                'event_timestamp' => 'timestamp',
                'tags' => 'Tag',
            ],
            'metadata' => true,
            'path' => '/events/%s',
        ],
        'objects' => [
            'rowKey' => 'Object',
            'model' => null,
            'modelAlias' => 'Object',
            'sortExcept' => [],
            'sortAliases' => [],
            'columns' => ['id', 'event_id', 'name', 'meta-category', 'comment', 'timestamp'],
            'count' => 'body',
            'aliases' => [
                'object_id' => 'id',
                'object_name' => 'name',
                'object_template_uuid' => 'template_uuid',
                'orgc_id' => 'Event.orgc_id',
            ],
            'metadata' => false,
            'path' => '/objects/%s',
        ],
        'galaxy_clusters' => [
            'rowKey' => 'GalaxyCluster',
            'model' => 'GalaxyCluster',
            'modelAlias' => 'GalaxyCluster',
            'sortExcept' => [],
            'sortAliases' => [],
            'columns' => ['id', 'value', 'Galaxy.name', 'Orgc.name', 'distribution', 'default'],
            'count' => 'body',
            'aliases' => [
                'org' => 'Orgc.name',
                'galaxy_uuid' => 'Galaxy.uuid',
                'galaxy_name' => 'Galaxy.name',
                'galaxy_namespace' => 'Galaxy.namespace',
            ],
            'metadata' => false,
            'path' => '/galaxy_clusters/%s',
        ],
        'event_reports' => [
            'rowKey' => 'EventReport',
            'model' => 'EventReport',
            'modelAlias' => 'EventReport',
            'sortExcept' => [],
            'sortAliases' => [],
            'columns' => ['id', 'event_id', 'name', 'Event.info', 'distribution', 'timestamp', 'Tag'],
            'count' => 'body',
            'aliases' => [
                'eventinfo' => 'Event.info',
                'org' => 'Event.Orgc.name',
                'org_id' => 'Event.org_id',
                'orgc_id' => 'Event.orgc_id',
                'date' => 'Event.date',
                'tags' => 'Tag',
            ],
            'metadata' => false,
            'path' => '/event_reports/%s',
        ],
        'notes' => [
            'rowKey' => 'Note',
            'model' => 'Note',
            'modelAlias' => 'Note',
            'sortExcept' => [],
            'sortAliases' => [],
            'columns' => ['id', 'object_type', 'object_uuid', 'note', 'authors', 'created'],
            'count' => 'body',
            'aliases' => ['org' => 'Orgc.name'],
            'metadata' => false,
            'path' => '/analyst_data/%s/Note',
        ],
        'opinions' => [
            'rowKey' => 'Opinion',
            'model' => 'Opinion',
            'modelAlias' => 'Opinion',
            'sortExcept' => [],
            'sortAliases' => [],
            'columns' => ['id', 'object_type', 'object_uuid', 'opinion', 'comment', 'authors'],
            'count' => 'body',
            'aliases' => ['org' => 'Orgc.name'],
            'metadata' => false,
            'path' => '/analyst_data/%s/Opinion',
        ],
        'relationships' => [
            'rowKey' => 'Relationship',
            'model' => 'Relationship',
            'modelAlias' => 'Relationship',
            'sortExcept' => [],
            'sortAliases' => [],
            'columns' => [
                'id', 'object_type', 'object_uuid', 'relationship_type', 'related_object_type',
                'related_object_uuid',
            ],
            'count' => 'body',
            'aliases' => ['org' => 'Orgc.name'],
            'metadata' => false,
            'path' => '/analyst_data/%s/Relationship',
        ],
        'collections' => [
            'rowKey' => 'Collection',
            'model' => 'Collection',
            'modelAlias' => 'Collection',
            'sortExcept' => [],
            'sortAliases' => [],
            'columns' => ['id', 'name', 'type', 'Orgc.name', 'distribution', 'element_count', 'modified'],
            'count' => 'body',
            'aliases' => ['org' => 'Orgc.name'],
            'metadata' => false,
            'path' => '/collections/%s',
        ],
        'tags' => [
            'rowKey' => 'Tag',
            'model' => 'Tag',
            'modelAlias' => 'Tag',
            'sortExcept' => [],
            'sortAliases' => [],
            'columns' => [
                'id', 'name', 'numerical_value', 'hide_tag', 'is_galaxy', 'count', 'attribute_count',
            ],
            'count' => 'body',
            'aliases' => [],
            'metadata' => false,
            'path' => '/tags/%s',
        ],
        'organisations' => [
            'rowKey' => 'Organisation',
            'model' => 'Organisation',
            'modelAlias' => 'Organisation',
            'sortExcept' => [],
            'sortAliases' => [],
            'columns' => ['id', 'name', 'type', 'nationality', 'sector', 'local', 'user_count'],
            'count' => 'body',
            'aliases' => [],
            'metadata' => false,
            'path' => '/organisations/%s',
        ],
    ];

    /** @var callable model class => its REST_SEARCH_ORDER_FIELDS */
    private $orderFields;

    /** @var array table => friendly sort name => server sort name */
    private $sortable = [];

    /**
     * @param callable|null $orderFields given a model class name, returns its
     *   REST_SEARCH_ORDER_FIELDS; by default the class constant
     */
    public function __construct(?callable $orderFields = null)
    {
        $this->orderFields = $orderFields ?? function ($model) {
            return constant($model . '::REST_SEARCH_ORDER_FIELDS');
        };
    }

    /**
     * @param string $name
     * @return bool
     */
    public function has($name)
    {
        return is_string($name) && isset(self::TABLES[$name]);
    }

    /**
     * @return string[]
     */
    public function names()
    {
        return array_keys(self::TABLES);
    }

    /**
     * @param string $name
     * @return array the table's definition
     */
    public function get($name)
    {
        return self::TABLES[$name];
    }

    /**
     * @param string $name
     * @return string restSearch's scope for the table, which is its row key
     */
    public function scope($name)
    {
        return self::TABLES[$name]['rowKey'];
    }

    /**
     * @param string $name
     * @return string the controller serving the table, as in its URLs
     */
    public function controller($name)
    {
        return explode('/', self::TABLES[$name]['path'])[1];
    }

    /**
     * @param string $name
     * @return string
     */
    public function search($name)
    {
        return sprintf(self::TABLES[$name]['path'], 'restSearch');
    }

    /**
     * @param string $name
     * @return string
     */
    public function discovery($name)
    {
        return sprintf(self::TABLES[$name]['path'], 'queryDescribe');
    }

    /**
     * @return array table => its discovery endpoint
     */
    public function discoveryEndpoints()
    {
        $endpoints = [];
        foreach (self::TABLES as $name => $table) {
            $endpoints[$name] = $this->discovery($name);
        }
        return $endpoints;
    }

    /**
     * @param string $name
     * @return array friendly sort name => server sort name, as validateOrder()
     *   and discovery() spell it
     */
    public function sortable($name)
    {
        if (isset($this->sortable[$name])) {
            return $this->sortable[$name];
        }
        $table = self::TABLES[$name];
        $fields = $table['model'] === null ? [] : ($this->orderFields)($table['model']);
        $sortable = [];
        foreach ($fields as $model => $names) {
            foreach ($names as $field) {
                $own = $model === $table['modelAlias'];
                $target = $own ? $field : "$model.$field";
                if ($own && !in_array($field, $table['sortExcept'], true)) {
                    $sortable[$field] = $field;
                }
                foreach ($table['sortAliases'] as $alias => $aliasTarget) {
                    if ($aliasTarget === $target) {
                        $sortable[$alias] = $target;
                    }
                }
            }
        }
        return $this->sortable[$name] = $sortable;
    }
}
