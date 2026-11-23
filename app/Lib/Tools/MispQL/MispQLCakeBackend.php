<?php
require_once __DIR__ . '/MispQLBackend.php';
App::uses('ComplexQueryTool', 'Tools');
App::uses('ComplexEventQueryTool', 'Tools');
App::uses('ComplexObjectQueryTool', 'Tools');

/**
 * MispQLBackend over MISP itself, as one user: the ACL of each table's
 * restSearch and queryDescribe, the field registries its queryDescribe and
 * restSearch use, and restSearch through AppController::_runRestSearch().
 */
class MispQLCakeBackend implements MispQLBackend
{
    const ANALYST_DATA = ['notes', 'opinions', 'relationships'];

    /** @var array */
    private $user;

    /** @var MispQLTables */
    private $tables;

    /** @var ACLComponent */
    private $acl;

    /** @var callable */
    private $runRestSearch;

    /**
     * @param array $user
     * @param MispQLTables $tables
     * @param ACLComponent $acl
     * @param callable $runRestSearch AppController::_runRestSearch()
     */
    public function __construct(array $user, MispQLTables $tables, $acl, callable $runRestSearch)
    {
        $this->user = $user;
        $this->tables = $tables;
        $this->acl = $acl;
        $this->runRestSearch = $runRestSearch;
    }

    /**
     * For MispQLTables: a model's REST_SEARCH_ORDER_FIELDS, the class loaded
     * through Cake.
     *
     * @param string $model
     * @return array
     */
    public static function orderFields($model)
    {
        App::uses($model, 'Model');
        return constant($model . '::REST_SEARCH_ORDER_FIELDS');
    }

    public function validate($table, array $body)
    {
        list($tool, $orderFields, $defaultModel) = $this->tool($table);
        $errors = [];
        if (isset($body['query'])) {
            try {
                $tool->validate($body['query']);
            } catch (ComplexQueryException $e) {
                $errors = $e->errors;
            }
        }
        if (!empty($body['order'])) {
            try {
                $tool->validateOrder($body['order'], $orderFields, $defaultModel);
            } catch (ComplexQueryException $e) {
                $errors = array_merge($errors, $e->errors);
            }
        }
        if (!empty($errors)) {
            throw new ComplexQueryException(array_slice($errors, 0, ComplexQueryTool::MAX_ERRORS));
        }
    }

    public function search($table, array $body)
    {
        $this->authorise($table, 'restSearch');
        $query = $body['query'] ?? null;
        unset($body['query']);
        // As restSearch harvests a JSON body
        foreach ($body as $key => $value) {
            if (is_string($value)) {
                $value = trim($value);
                $body[$key] = strpos($value, '||') ? explode('||', $value) : $value;
            }
        }
        // As restSearch answers a client that accepts application/json
        if (empty($body['returnFormat'])) {
            $body['returnFormat'] = 'json';
        }
        return ($this->runRestSearch)(
            $this->tables->scope($table),
            $body,
            $query,
            $this->user,
            Inflector::camelize($this->tables->controller($table))
        );
    }

    public function describe($table)
    {
        $this->authorise($table, 'queryDescribe');
        list($tool, $orderFields, $defaultModel) = $this->tool($table);
        return $tool->discovery($table, $this->tables->search($table), $orderFields, $defaultModel);
    }

    public function tables()
    {
        $tables = [];
        foreach ($this->tables->names() as $table) {
            try {
                $this->authorise($table, 'queryDescribe');
            } catch (ForbiddenException $e) {
                continue;
            }
            $tables[] = $table;
        }
        return $tables;
    }

    public function whoami()
    {
        return [
            'email' => $this->user['email'],
            'role' => $this->user['Role']['name'] ?? null,
            'org' => $this->user['Organisation']['name'] ?? null,
        ];
    }

    /**
     * @throws ForbiddenException
     */
    private function authorise($table, $action)
    {
        $this->acl->checkAccess($this->user, $this->tables->controller($table), $action, false);
    }

    /**
     * The validator the table's restSearch and queryDescribe build.
     *
     * @return array the tool, the sortable fields and the model they are
     *   named without
     */
    private function tool($table)
    {
        $limits = ComplexQueryTool::limitsFromConfig();
        switch ($table) {
            case 'attributes':
                return [
                    new ComplexQueryTool(ClassRegistry::init('MispAttribute'), $limits),
                    MispAttribute::REST_SEARCH_ORDER_FIELDS,
                    'Attribute',
                ];
            case 'events':
                return [
                    new ComplexEventQueryTool(ClassRegistry::init('Event')->Attribute, $this->user, $limits),
                    Event::REST_SEARCH_ORDER_FIELDS,
                    'Event',
                ];
            case 'objects':
                return [
                    new ComplexObjectQueryTool(ClassRegistry::init('MispObject')->Attribute, $this->user, $limits),
                    [],
                    'Object',
                ];
        }
        $class = $this->tables->get($table)['model'];
        $model = ClassRegistry::init($class);
        $fields = in_array($table, self::ANALYST_DATA, true) ? $model->queryFields() : $class::QUERY_FIELDS;
        return [
            new ComplexQueryTool($model, $limits, $fields),
            $class::REST_SEARCH_ORDER_FIELDS,
            $this->tables->scope($table),
        ];
    }
}
