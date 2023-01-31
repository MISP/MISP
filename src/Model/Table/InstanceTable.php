<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use Cake\ORM\Table;
use Cake\ORM\TableRegistry;
use Cake\Validation\Validator;
use Migrations\Migrations;
use Cake\Filesystem\Folder;
use Cake\Http\Exception\MethodNotAllowedException;

class InstanceTable extends AppTable
{
    protected $activePlugins = ['Tags', 'ADmad/SocialAuth'];
    public $seachAllTables = [];

    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');
        $this->setDisplayField('name');
        $this->setSearchAllTables();
    }

    public function validationDefault(Validator $validator): Validator
    {
        return $validator;
    }

    public function setSearchAllTables(): void
    {
        $this->seachAllTables = [
            'Broods' => ['conditions' => false, 'afterFind' => false],
            'Individuals' => ['conditions' => false, 'afterFind' => false],
            'Organisations' => ['conditions' => false, 'afterFind' => false],
            'SharingGroups' => [
                'conditions' => false,
                'afterFind' => function($result, $user) {
                    foreach ($result as $i => $row) {
                        if (empty($user['role']['perm_admin'])) {
                            $orgFound = false;
                            if (!empty($row['sharing_group_orgs'])) {
                                foreach ($row['sharing_group_orgs'] as $org) {
                                    if ($org['id'] === $user['organisation_id']) {
                                        $orgFound = true;
                                    }
                                }
                            }
                            if ($row['organisation_id'] !== $user['organisation_id'] && !$orgFound) {
                                unset($result[$i]);
                            }
                        }
                    }
                    return $result;
                },
            ],
            'Users' => [
                'conditions' => function($user) {
                    $conditions = [];
                    if (empty($user['role']['perm_admin'])) {
                        $conditions['Users.organisation_id'] = $user['organisation_id'];
                    }
                    return $conditions;
                },
                'afterFind' => function ($result, $user) {
                    return $result;
                },
            ],
            'EncryptionKeys' => ['conditions' => false, 'afterFind' => false],
        ];
    }

    public function getStatistics(int $days=30): array
    {
        $models = ['Individuals', 'Organisations', 'Alignments', 'EncryptionKeys', 'SharingGroups', 'Users', 'Broods', 'Tags.Tags'];
        foreach ($models as $model) {
            $table = TableRegistry::getTableLocator()->get($model);
            $statistics[$model] = $this->getActivityStatisticsForModel($table, $days);
        }
        return $statistics;
    }

    public function searchAll($value, $user, $limit=5, $model=null)
    {
        $results = [];
        $models = $this->seachAllTables;
        if (!is_null($model)) {
            if (in_array($model, array_keys($this->seachAllTables))) {
                $models = [$model => $this->seachAllTables[$model]];
            } else {
                return $results; // Cannot search in this model
            }
        }

        // search in metafields. FIXME?: Use meta-fields type handler to search for meta-field values
        if (is_null($model)) {
            $metaFieldTable = TableRegistry::get('MetaFields');
            $query = $metaFieldTable->find()->where([
                'value LIKE' => '%' . $value . '%'
            ]);
            $results['MetaFields']['amount'] = $query->count();
            $result = $query->limit($limit)->all()->toList();
            if (!empty($result)) {
                $results['MetaFields']['entries'] = $result;
            }
        }

        foreach ($models as $tableName => $tableConfig) {
            $controller = $this->getController($tableName);
            $table = TableRegistry::get($tableName);
            $query = $table->find();
            $quickFilters = $this->getQuickFiltersFieldsFromController($controller);
            $containFields = $this->getContainFieldsFromController($controller);
            if (empty($quickFilters)) {
                continue; // make sure we are filtering on something
            }
            $params = ['quickFilter' => $value];
            $quickFilterOptions = ['quickFilters' => $quickFilters];
            $query = $controller->CRUD->setQuickFilters($params, $query, $quickFilterOptions);
            if (!empty($tableConfig['conditions'])) {
                $whereClause = [];
                if (is_callable($tableConfig['conditions'])) {
                    $whereClause = $tableConfig['conditions']($user);
                } else {
                    $whereClause = $tableConfig['conditions'];
                }
                $query->where($whereClause);
            }
            if (!empty($containFields)) {
                $query->contain($containFields);
            }
            if (!empty($tableConfig['contain'])) {
                $query->contain($tableConfig['contain']);
            }
            if (empty($tableConfig['afterFind'])) {
                $results[$tableName]['amount'] = $query->count();
            }
            $result = $query->limit($limit)->all()->toList();
            if (!empty($result)) {
                if (!empty($tableConfig['afterFind'])) {
                    $result = $tableConfig['afterFind']($result, $user);
                }
                $results[$tableName]['entries'] = $result;
                $results[$tableName]['amount'] = count($result);
            }
        }
        return $results;
    }

    public function getController($name)
    {
        $controllerName = "\\App\\Controller\\{$name}Controller";
        if (!class_exists($controllerName)) {
            throw new MethodNotAllowedException(__('Model `{0}` does not exists', $name));
        }
        $controller = new $controllerName;
        return $controller;
    }

    public function getQuickFiltersFieldsFromController($controller)
    {
        return !empty($controller->quickFilterFields) ? $controller->quickFilterFields : [];
    }

    public function getContainFieldsFromController($controller)
    {
        return !empty($controller->containFields) ? $controller->containFields : [];
    }

    public function getMigrationStatus()
    {
        $migrations = new Migrations();
        $status = $migrations->status();
        foreach ($this->activePlugins as $pluginName) {
            $pluginStatus = $migrations->status([
                'plugin' => $pluginName
            ]);
            $pluginStatus = array_map(function ($entry) use ($pluginName) {
                $entry['plugin'] = $pluginName;
                return $entry;
            }, $pluginStatus);
            $status = array_merge($status, $pluginStatus);
        }
        $status = array_reverse($status);

        $updateAvailables = array_filter($status, function ($update) {
            return $update['status'] != 'up';
        });
        return [
            'status' => $status,
            'updateAvailables' => $updateAvailables,
        ];
    }

    public function migrate($version=null) {
        $migrations = new Migrations();
        if (is_null($version)) {
            $migrationResult = $migrations->migrate();
        } else {
            $migrationResult = $migrations->migrate(['target' => $version]);
        }
        $command = ROOT . '/bin/cake schema_cache clear';
        $output = shell_exec($command);
        return [
            'success' => true
        ];
    }

    public function rollback($version=null) {
        $migrations = new Migrations();
        if (is_null($version)) {
            $migrationResult = $migrations->rollback();
        } else {
            $migrationResult = $migrations->rollback(['target' => $version]);
        }
        return [
            'success' => true
        ];
    }

    public function getAvailableThemes()
    {
        $themesPath = ROOT . '/webroot/css/themes';
        $dir = new Folder($themesPath);
        $filesRegex = 'bootstrap-(?P<themename>\w+)\.css';
        $themeRegex = '/' . 'bootstrap-(?P<themename>\w+)\.css' . '/';
        $files = $dir->find($filesRegex);
        $themes = [];
        foreach ($files as $filename) {
            $matches = [];
            $themeName = preg_match($themeRegex, $filename, $matches);
            if (!empty($matches['themename'])) {
                $themes[] =  $matches['themename'];
            }
        }
        return $themes;
    }
}
