<?php
App::uses('AppModel', 'Model');

/**
 * @property GalaxyCluster $GalaxyCluster
 */
class GalaxyElement extends AppModel
{
    public $useTable = 'galaxy_elements';

    public $recursive = -1;

    public $actsAs = array(
        'AuditLog',
            'Containable',
    );

    public $belongsTo = array(
            'GalaxyCluster' => array(
                'className' => 'GalaxyCluster',
                'foreignKey' => 'galaxy_cluster_id',
            )
    );

    public function updateElements($oldClusterId, $newClusterId, $elements, $delete=true)
    {
        if ($delete) {
            $this->deleteAll(array('GalaxyElement.galaxy_cluster_id' => $oldClusterId));
        }
        $tempElements = array();
        foreach ($elements as $key => $value) {
            if (is_array($value)) {
                foreach ($value as $arrayElement) {
                    $tempElements[] = array(
                        'key' => $key,
                        'value' => $arrayElement,
                        'galaxy_cluster_id' => $newClusterId
                    );
                }
            } else {
                $tempElements[] = array(
                    'key' => $key,
                    'value' => $value,
                    'galaxy_cluster_id' => $newClusterId
                );
            }
        }
        $this->saveMany($tempElements);
    }

    public function captureElements($user, $elements, $clusterId)
    {
        $tempElements = array();
        foreach ($elements as $k => $element) {
            $tempElements[] = array(
                'key' => $element['key'],
                'value' => $element['value'],
                'galaxy_cluster_id' => $clusterId,
            );
        }
        $this->saveMany($tempElements);
    }

    public function buildACLConditions($user)
    {
        $conditions = [];
        if (!$user['Role']['perm_site_admin']) {
            $conditions = $this->GalaxyCluster->buildConditions($user);
        }
        return $conditions;
    }

    public function buildClusterConditions($user, $clusterId)
    {
        return [
            $this->buildACLConditions($user),
            'GalaxyCluster.id' => $clusterId
        ];
    }

    public function fetchElements(array $user, $clusterId)
    {
        $params = array(
            'conditions' => $this->buildClusterConditions($user, $clusterId),
            'contain' => ['GalaxyCluster' => ['fields' => ['id', 'distribution', 'org_id']]],
            'recursive' => -1
        );
        $elements = $this->find('all', $params);
        foreach ($elements as $i => $element) {
            $elements[$i] = $elements[$i]['GalaxyElement'];
            unset($elements[$i]['GalaxyCluster']);
            unset($elements[$i]['GalaxyElement']);
        }
        return $elements;
    }

    /**
     * The element keys a galaxy's clusters can be filtered on, with the values
     * offered for each, most used first. Only clusters the user can see count.
     *
     * @param array $user
     * @param int $galaxyId
     * @return array key => ['label' => string, 'values' => string[]]
     */
    public function filterFacets(array $user, $galaxyId)
    {
        App::uses('GalaxyElementFacets', 'Tools');
        $query = [
            'recursive' => -1,
            'joins' => [[
                'table' => 'galaxy_clusters',
                'alias' => 'GalaxyCluster',
                'type' => 'INNER',
                'conditions' => ['GalaxyCluster.id = GalaxyElement.galaxy_cluster_id'],
            ]],
            'conditions' => [
                'AND' => [
                    $this->GalaxyCluster->buildConditions($user),
                    'GalaxyCluster.galaxy_id' => $galaxyId,
                    'GalaxyCluster.deleted' => 0,
                ],
            ],
        ];
        $rows = $this->find('all', $query + [
            'fields' => [
                'GalaxyElement.key',
                'COUNT(*) AS n',
                'COUNT(DISTINCT GalaxyElement.galaxy_cluster_id) AS clusters',
                'COUNT(DISTINCT LEFT(GalaxyElement.value, ' . GalaxyElementFacets::MAX_VALUE_LENGTH . ')) AS distinct_values',
            ],
            'group' => ['GalaxyElement.key'],
        ]);
        $summaries = [];
        foreach ($rows as $row) {
            $summaries[$row['GalaxyElement']['key']] = [
                'rows' => (int)$row[0]['n'],
                'clusters' => (int)$row[0]['clusters'],
                'values' => (int)$row[0]['distinct_values'],
            ];
        }
        $keys = GalaxyElementFacets::selectKeys($summaries);
        if (empty($keys)) {
            return [];
        }

        $query['conditions']['AND']['GalaxyElement.key'] = $keys;
        $query['conditions']['AND']['CHAR_LENGTH(GalaxyElement.value) <='] = GalaxyElementFacets::MAX_VALUE_LENGTH;
        $valueField = 'LEFT(GalaxyElement.value, ' . GalaxyElementFacets::MAX_VALUE_LENGTH . ')';
        $rows = $this->find('all', $query + [
            'fields' => ['GalaxyElement.key', $valueField . ' AS value', 'COUNT(*) AS n'],
            'group' => ['GalaxyElement.key', $valueField],
        ]);
        $counts = array_fill_keys($keys, []);
        foreach ($rows as $row) {
            $value = (string)$row[0]['value'];
            if (GalaxyElementFacets::isUsableValue($value)) {
                $counts[$row['GalaxyElement']['key']][$value] = (int)$row[0]['n'];
            }
        }
        $facets = [];
        foreach ($counts as $key => $values) {
            if (count($values) < 2) {
                continue;
            }
            uksort($values, function ($a, $b) use ($values) {
                return [$values[$b], $a] <=> [$values[$a], $b];
            });
            $facets[$key] = [
                'label' => GalaxyElementFacets::label($key),
                'values' => array_map('strval', array_keys($values)),
            ];
        }
        return $facets;
    }

    /**
     * @param int $galaxyId
     * @param string $key
     * @param string[] $values
     * @return int[] the galaxy's clusters carrying any of the values under that key
     */
    public function clusterIdsWithValue($galaxyId, $key, array $values)
    {
        return $this->find('column', [
            'recursive' => -1,
            'fields' => ['GalaxyElement.galaxy_cluster_id'],
            'joins' => [[
                'table' => 'galaxy_clusters',
                'alias' => 'GalaxyCluster',
                'type' => 'INNER',
                'conditions' => ['GalaxyCluster.id = GalaxyElement.galaxy_cluster_id'],
            ]],
            'conditions' => [
                'GalaxyCluster.galaxy_id' => $galaxyId,
                'GalaxyElement.key' => $key,
                'GalaxyElement.value' => array_values($values),
            ],
            'unique' => true,
        ]);
    }

    public function getExpandedJSONFromElements($elements)
    {
        $keyedValue = [];
        foreach ($elements as $i => $element) {
            $keyedValue[$element['GalaxyElement']['key']][] = $element['GalaxyElement']['value'];
        }
        $expanded = Hash::expand($keyedValue);
        return $expanded;
    }

    /**
     * getClusterIDsFromMatchingElements
     *
     * @param array $user
     * @param array $elements an associative array containing the elements to search for
     *  Example: {"synonyms": "apt42"}
     * @return array
     */
    public function getClusterIDsFromMatchingElements(array $user, array $elements): array
    {
        $conditionCount = 0;
        $elementConditions = [];
        foreach ($elements as $key => $value) {
            if (is_array($value)) {
                foreach ($value as $arrayElement) {
                    if (strpos($arrayElement, '%') !== false) {
                        $elementConditions['OR'][] = [
                            'GalaxyElement.key' => $key,
                            'GalaxyElement.value LIKE' => $arrayElement,
                        ];
                    } else {
                        $elementConditions['OR'][] = [
                            'GalaxyElement.key' => $key,
                            'GalaxyElement.value' => $arrayElement,
                        ];
                    }
                }
                $conditionCount++;
            } else {
                    if (strpos($value, '%') !== false) {
                        $elementConditions['OR'][] = [
                            'GalaxyElement.key' => $key,
                            'GalaxyElement.value LIKE' => $value,
                        ];
                    } else {
                        $elementConditions['OR'][] = [
                            'GalaxyElement.key' => $key,
                            'GalaxyElement.value' => $value,
                        ];
                    }
                    $conditionCount++;
            }
        }
        $conditions = [
            $this->buildACLConditions($user),
            $elementConditions,
        ];
        $elements = $this->find('all', [
            'fields' => ['GalaxyElement.galaxy_cluster_id'],
            'conditions' => $conditions,
            'contain' => ['GalaxyCluster' => ['fields' => ['id', 'distribution', 'org_id']]],
            'group' => ['GalaxyElement.galaxy_cluster_id'],
            'having' => ['COUNT(GalaxyElement.id) >=' => $conditionCount],
            'recursive' => -1
        ]);
        $clusterIDs = [];
        foreach ($elements as $element) {
            $clusterIDs[] = $element['GalaxyElement']['galaxy_cluster_id'];
        }
        return $clusterIDs;
    }
}
