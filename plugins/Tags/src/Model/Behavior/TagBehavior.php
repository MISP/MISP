<?php

namespace Tags\Model\Behavior;

use Cake\ORM\Behavior;
use Cake\ORM\Entity;
use Cake\ORM\Query;
use Cake\ORM\Table;

class TagBehavior extends Behavior
{
    protected $_defaultConfig = [
        'finderField' => 'name',
        'tagsAssoc' => [
            'className' => 'Tags.Tags',
            'joinTable' => 'tags_tagged',
            'foreignKey' => 'fk_id',
            'targetForeignKey' => 'tag_id',
            'propertyName' => 'tags',
        ],
        'tagsCounter' => ['counter'],
        'taggedAssoc' => [
            'className' => 'Tags.Tagged',
            'foreignKey' => 'fk_id'
        ],
        'implementedEvents' => [
            'Model.beforeMarshal' => 'beforeMarshal',
            'Model.beforeFind' => 'beforeFind',
            'Model.beforeSave' => 'beforeSave',
        ],
        'implementedMethods' => [
            'normalizeTags' => 'normalizeTags',
        ],
        'implementedFinders' => [
            'tagged' => 'findByTag',
            'untagged' => 'findUntagged',
        ],
    ];

    public function initialize(array $config): void {
        $this->bindAssociations();
        $this->attachCounters();
    }

    public function bindAssociations() {
        $config = $this->getConfig();
        $tagsAssoc = $config['tagsAssoc'];
        $taggedAssoc = $config['taggedAssoc'];

        $table = $this->_table;
        $tableAlias = $this->_table->getAlias();

        $assocConditions = ['Tagged.fk_model' => $tableAlias];

        if (!$table->hasAssociation('Tagged')) {
            $table->hasMany('Tagged', array_merge(
                $taggedAssoc,
                [
                    'conditions' => $assocConditions
                ]
            ));
        }

        if (!$table->hasAssociation('Tags')) {
            $table->belongsToMany('Tags', array_merge(
                $tagsAssoc,
                [
                    'through' => $table->Tagged->getTarget(),
                    'conditions' => $assocConditions,
                ]
            ));
        }

        if (!$table->Tags->hasAssociation($tableAlias)) {
            $table->Tags->belongsToMany($tableAlias, array_merge(
                $tagsAssoc,
                [
                    'className' => get_class($table),
                ]
            ));
        }

        if (!$table->Tagged->hasAssociation($tableAlias)) {
            $table->Tagged->belongsTo($tableAlias, [
                'className' => get_class($table),
                'foreignKey' => $tagsAssoc['foreignKey'],
                'conditions' => $assocConditions,
                'joinType' => 'INNER',
            ]);
        }

        if (!$table->Tagged->hasAssociation($tableAlias . 'Tags')) {
            $table->Tagged->belongsTo($tableAlias . 'Tags', [
                'className' => $tagsAssoc['className'],
                'foreignKey' => $tagsAssoc['targetForeignKey'],
                'conditions' => $assocConditions,
                'joinType' => 'INNER',
            ]);
        }
    }

    public function attachCounters() {
        $config = $this->getConfig();
        $taggedTable = $this->_table->Tagged;

        if (!$taggedTable->hasBehavior('CounterCache')) {
            $taggedTable->addBehavior('CounterCache', [
                'Tags' => $config['tagsCounter']
            ]);
        }
    }

    public function beforeMarshal($event, $data, $options) {
        $property = $this->getConfig('tagsAssoc.propertyName');
        $options['accessibleFields'][$property] = true;
        $options['associated']['Tags']['accessibleFields']['id'] = true;
        if (isset($data['tags'])) {
            if (!empty($data['tags'])) {
                $data[$property] = $this->normalizeTags($data['tags']);
            }
        }
    }

    public function beforeSave($event, $entity, $options)
    {
        if (empty($entity->tags)) {
            return;
        }
        foreach ($entity->tags as $k => $tag) {
            if (!$tag->isNew()) {
                continue;
            }
            $existingTag = $this->getExistingTag($tag->name);
            if (!$existingTag) {
                continue;
            }

            $joinData = $tag->_joinData;
            $tag = $existingTag;
            $tag->_joinData = $joinData;
            $entity->tags[$k] = $tag;
        }
    }

    public function normalizeTags($tags) {

        $result = [];
        $modelAlias = $this->_table->getAlias();
        $common = [
            '_joinData' => [
                'fk_model' => $modelAlias
            ]
        ];

        $tagsTable = $this->_table->Tags;
        $displayField = $tagsTable->getDisplayField();

        $tagIdentifiers = [];
        foreach ($tags as $tag) {
            if (empty($tag)) {
                continue;
            }
            if (is_object($tag)) {
                $result[] = $tag->toArray();
            }
            $tagIdentifier = $this->getTagIdentifier($tag);
            if (isset($tagIdentifiers[$tagIdentifier])) {
                continue;
            }
            $tagIdentifiers[$tagIdentifier] = true;

            $existingTag = $this->getExistingTag($tagIdentifier);
            if ($existingTag) {
                $result[] = array_merge($common, ['id' => $existingTag->id]);
                continue;
            }
            $result[] = array_merge(
                $common,
                [
                    'name' => $tagIdentifier,
                    'colour' => '#924da6'
                ]
            );
        }
        return $result;
    }

    protected function getTagIdentifier($tag)
    {
        if (is_object($tag)) {
            return $tag->name;
        } else {
            return trim($tag);
        }
    }

    protected function getExistingTag($tagName)
    {
        $tagsTable = $this->_table->Tags->getTarget();
        $query = $tagsTable->find()->where([
            'Tags.name' => $tagName
        ])
        ->select('Tags.id');
        return $query->first();
    }

    public function findByTag(Query $query, array $options) {
        $finderField = $optionsKey = $this->getConfig('finderField');
        if (!$finderField) {
            $finderField = $optionsKey = 'name';
        }

        if (!isset($options[$optionsKey])) {
            throw new RuntimeException(__('Expected key `{0}` not present in find(\'tagged\') options argument.', $optionsKey));
        }
        $isAndOperator = isset($options['OperatorAND']) ? $options['OperatorAND'] : true;
        $filterValue = $options[$optionsKey];
        if (!$filterValue) {
            return $query;
        }

        $filterValue = $this->dissectArgs($filterValue);
        if (!empty($filterValue['NOT']) || !empty($filterValue['LIKE'])) {
            return $this->findByComplexQueryConditions($query, $filterValue, $finderField, $isAndOperator);
        }

        $subQuery = $this->buildQuerySnippet($filterValue, $finderField, $isAndOperator);
        if (is_string($subQuery)) {
            $query->matching('Tags', function ($q) use ($finderField, $subQuery) {
                $key = 'Tags.' . $finderField;
                return $q->where([
                    $key => $subQuery,
                ]);
            });
            return $query;
        }

        $modelAlias = $this->_table->getAlias();
        return $query->where([$modelAlias . '.id IN' => $subQuery]);
    }

    public function findUntagged(Query $query, array $options) {
        $modelAlias = $this->_table->getAlias();
        $foreignKey = $this->getConfig('tagsAssoc.foreignKey');
        $conditions = ['fk_model' => $modelAlias];
        $this->_table->hasOne('NoTags', [
            'className' => $this->getConfig('taggedAssoc.className'),
            'foreignKey' => $foreignKey,
            'conditions' => $conditions
        ]);
        $query = $query->contain(['NoTags'])->where(['NoTags.id IS' => null]);
        return $query;
    }

    protected function dissectArgs($filterValue): array
    {
        if (!is_array($filterValue)) {
            return $filterValue;
        }
        $dissected = [
            'AND' => [],
            'NOT' => [],
            'LIKE' => [],
        ];
        foreach ($filterValue as $value) {
            if (substr($value, 0, 1) == '!') {
                $dissected['NOT'][] = substr($value, 1);
            }
            else if (strpos($value, '%') != false) {
                $dissected['LIKE'][] = $value;
            } else {
                $dissected['AND'][] = $value;
            }
        }
        if (empty($dissected['NOT']) && empty($dissected['LIKE'])) {
            return $dissected['AND'];
        }
        return $dissected;
    }

    protected function buildQuerySnippet($filterValue, string $finderField, bool $OperatorAND=true)
    {
        if (!is_array($filterValue)) {
            return $filterValue;
        }
        $key = 'Tags.' . $finderField;
        $foreignKey = $this->getConfig('tagsAssoc.foreignKey');
        $conditions = [
            $key . ' IN' => $filterValue,
        ];

        $query = $this->_table->Tagged->find();
        if ($OperatorAND) {
            $query->contain(['Tags'])
                ->group('Tagged.' . $foreignKey)
                ->having('COUNT(*) = ' . count($filterValue))
                ->select('Tagged.' . $foreignKey)
                ->where($conditions);
        } else {
            $query->contain(['Tags'])
                ->select('Tagged.' . $foreignKey)
                ->where($conditions);
        }
        return $query;
    }

    protected function findByComplexQueryConditions($query, $filterValue, string $finderField, bool $OperatorAND=true)
    {
        $key = 'Tags.' . $finderField;
        $taggedAlias = 'Tagged';
        $foreignKey = $this->getConfig('tagsAssoc.foreignKey');

        if (!empty($filterValue['AND'])) {
            $subQuery = $this->buildQuerySnippet($filterValue['AND'], $finderField, $OperatorAND);
            $modelAlias = $this->_table->getAlias();
            $query->where([$modelAlias . '.id IN' => $subQuery]);
        }

        if (!empty($filterValue['NOT'])) {
            $subQuery = $this->buildQuerySnippet($filterValue['NOT'], $finderField, false);
            $modelAlias = $this->_table->getAlias();
            $query->where([$modelAlias . '.id NOT IN' => $subQuery]);
        }

        if (!empty($filterValue['LIKE'])) {
            $conditions = ['OR' => []];
            foreach($filterValue['LIKE'] as $likeValue) {
                $conditions['OR'][] = [
                    $key . ' LIKE' => $likeValue,
                ];
            }
            $subQuery = $this->buildQuerySnippet($filterValue['NOT'], $finderField, $OperatorAND);
            if ($OperatorAND) {
                $subQuery = $this->_table->Tagged->find()
                    ->contain(['Tags'])
                    ->group('Tagged.' . $foreignKey)
                    ->having('COUNT(*) >= ' . count($filterValue['LIKE']))
                    ->select('Tagged.' . $foreignKey)
                    ->where($conditions);
            } else {
                $subQuery = $this->_table->Tagged->find()
                    ->contain(['Tags'])
                    ->select('Tagged.' . $foreignKey)
                    ->where($conditions);
            }
            $modelAlias = $this->_table->getAlias();
            $query->where([$modelAlias . '.id IN' => $subQuery]);
        }

        return $query;
    }
}
