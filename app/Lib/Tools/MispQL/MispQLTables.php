<?php

/**
 * What MispQL knows of each table: its endpoints, where its rows sit, its
 * default columns, how it is counted, the names it can be sorted by and the
 * columns naming a record the console links to.
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
            'links' => [
                'id' => 'Attribute',
                'uuid' => 'Attribute',
                'value' => 'Value',
                'event_id' => 'Event',
                'Event.id' => 'Event',
                'Event.uuid' => 'Event',
                'object_id' => 'Object',
                'Object.id' => 'Object',
                'Object.uuid' => 'Object',
            ],
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
            'links' => [
                'id' => 'Event',
                'uuid' => 'Event',
                'extends_uuid' => 'Event',
            ],
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
            'links' => [
                'id' => 'Object',
                'uuid' => 'Object',
                'event_id' => 'Event',
                'Event.id' => 'Event',
                'Event.uuid' => 'Event',
            ],
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
            'links' => [
                'id' => 'GalaxyCluster',
                'uuid' => 'GalaxyCluster',
                'galaxy_id' => 'Galaxy',
                'Galaxy.id' => 'Galaxy',
                'Galaxy.uuid' => 'Galaxy',
            ],
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
            'links' => [
                'id' => 'EventReport',
                'uuid' => 'EventReport',
                'event_id' => 'Event',
                'Event.id' => 'Event',
                'Event.uuid' => 'Event',
            ],
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
            'links' => [
                'id' => 'Note',
                'uuid' => 'Note',
                'object_uuid' => ['type_from' => 'object_type'],
                'object_sha256' => ['type' => 'Value', 'by' => 'sha256'],
            ],
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
            'links' => [
                'id' => 'Opinion',
                'uuid' => 'Opinion',
                'object_uuid' => ['type_from' => 'object_type'],
                'object_sha256' => ['type' => 'Value', 'by' => 'sha256'],
            ],
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
            'links' => [
                'id' => 'Relationship',
                'uuid' => 'Relationship',
                'object_uuid' => ['type_from' => 'object_type'],
                'object_sha256' => ['type' => 'Value', 'by' => 'sha256'],
                'related_object_uuid' => ['type_from' => 'related_object_type'],
                'related_object_sha256' => ['type' => 'Value', 'by' => 'sha256'],
            ],
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
            'links' => ['id' => 'Collection', 'uuid' => 'Collection'],
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
            'links' => ['id' => 'Tag'],
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
            'links' => ['id' => 'Organisation', 'uuid' => 'Organisation'],
        ],
    ];

    /** Organisation columns, linked wherever a table's rows carry them. */
    const ORGANISATION_LINKS = [
        'org_id', 'orgc_id', 'org_uuid', 'orgc_uuid',
        'Org.id', 'Org.uuid', 'Orgc.id', 'Orgc.uuid',
        'Event.org_id', 'Event.orgc_id',
        'Event.Org.id', 'Event.Org.uuid', 'Event.Orgc.id', 'Event.Orgc.uuid',
    ];

    /**
     * The page of each kind of record a cell can name, and the table whose
     * access it follows (null: every user). `%s` takes the id, the uuid or,
     * for a value, its address.
     */
    const PAGES = [
        'Attribute' => ['/attributes/view/%s', 'attributes'],
        'Event' => ['/events/view/%s', 'events'],
        'Object' => ['/objects/view/%s', 'objects'],
        'GalaxyCluster' => ['/galaxy_clusters/view/%s', 'galaxy_clusters'],
        'Galaxy' => ['/galaxies/view/%s', 'galaxy_clusters'],
        'EventReport' => ['/eventReports/view/%s', 'event_reports'],
        'Note' => ['/analystData/view/Note/%s', 'notes'],
        'Opinion' => ['/analystData/view/Opinion/%s', 'opinions'],
        'Relationship' => ['/analystData/view/Relationship/%s', 'relationships'],
        'Collection' => ['/collections/view/%s', 'collections'],
        'Tag' => ['/events/index/searchtag:%s', 'events'],
        'Organisation' => ['/organisations/view/%s', 'organisations'],
        'Value' => ['/values/view/%s', null],
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
     * @return array column, as the rows name it => the record it names: a
     *   record type, ['type_from' => column holding the type], or
     *   ['type' => 'Value', 'by' => 'sha256']
     */
    public function links($name)
    {
        return self::TABLES[$name]['links'] + array_fill_keys(self::ORGANISATION_LINKS, 'Organisation');
    }

    /**
     * @param string[] $tables the tables the user may query
     * @return array record type => its page, for the records the user may
     *   search for
     */
    public function pages(array $tables)
    {
        $pages = [];
        foreach (self::PAGES as $type => list($url, $table)) {
            if ($table === null || in_array($table, $tables, true)) {
                $pages[$type] = $url;
            }
        }
        return $pages;
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
