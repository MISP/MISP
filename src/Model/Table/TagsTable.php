<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use Cake\Core\Configure;

class TagsTable extends AppTable
{
    public function initialize(array $config): void
    {
        $this->setDisplayField('name');

        $this->belongsTo(
            'Organisation',
            [
                'className' => 'Organisations',
                'foreignKey' => 'org_id',
                'propertyName' => 'Organisation'
            ]
        );
        $this->belongsTo(
            'User',
            [
                'className' => 'Users',
                'foreignKey' => 'user_id',
                'propertyName' => 'User'
            ]
        );
        $this->belongsTo(
            'Org',
            [
                'className' => 'Organisations',
                'foreignKey' => 'org_id',
                'propertyName' => 'Org'
            ]
        );
        $this->belongsTo(
            'Orgc',
            [
                'className' => 'Organisations',
                'foreignKey' => 'orgc_id',
                'propertyName' => 'Orgc'
            ]
        );
        $this->belongsTo(
            'SharingGroup',
            [
                'className' => 'SharingGroups',
                'foreignKey' => 'sharing_group_id',
                'propertyName' => 'SharingGroup'
            ]
        );

        $this->hasMany(
            'EventTag',
            [
                'className' => 'EventTags',
            ]
        );
        $this->hasMany('TemplateTag');
        $this->hasMany('AttributeTag');
        $this->hasMany('TagCollectionTag');
        $this->hasMany('GalaxyClusterRelationTag');
    }

    /**
     * @param array $tag
     * @param array $user
     * @param bool $force
     * @return false|int
     * @throws Exception
     */
    public function captureTag(array $tag, array $user, $force = false)
    {
        $existingTag = $this->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => ['LOWER(name)' => mb_strtolower($tag['name'])],
                'fields' => ['id', 'org_id', 'user_id'],
                'callbacks' => false,
            ]
        )->first();
        if (empty($existingTag)) {
            if ($force || $user['Role']['perm_tag_editor']) {
                if (empty($tag['colour'])) {
                    $tag['colour'] = $this->tagColor($tag['name']);
                }
                $tagEntity = $this->newEntity(
                    [
                        'name' => $tag['name'],
                        'colour' => $tag['colour'],
                        'exportable' => isset($tag['exportable']) ? $tag['exportable'] : 1,
                        'local_only' => $tag['local_only'] ?? 0,
                        'org_id' => 0,
                        'user_id' => 0,
                        'hide_tag' => Configure::read('MISP.incoming_tags_disabled_by_default') ? 1 : 0
                    ]
                );
                $this->save($tagEntity);
                return $tagEntity->id;
            } else {
                return false;
            }
        }
        if (
            !$user['Role']['perm_site_admin'] &&
            (
                (
                    $existingTag['org_id'] != 0 &&
                    $existingTag['org_id'] != $user['org_id']
                ) ||
                (
                    $existingTag['user_id'] != 0 &&
                    $existingTag['user_id'] != $user['id']
                )
            )
        ) {
            return false;
        }
        return $existingTag['id'];
    }

    /**
     * Generate tag color according to name. So color will be same on all instances.
     * @param string $tagName
     * @return string
     */
    public function tagColor($tagName)
    {
        return '#' . substr(md5($tagName), 0, 6);
    }

    /**
     * @param string $name
     * @param string|false $colour
     * @param null $numerical_value
     * @return int|false Created tag ID or false on error
     * @throws Exception
     */
    public function quickAdd($name, $colour = false, $numerical_value = null)
    {
        if ($colour === false) {
            $colour = $this->tagColor($name);
        }
        $data = [
            'name' => $name,
            'colour' => $colour,
            'exportable' => 1,
        ];
        if ($numerical_value !== null) {
            $data['numerical_value'] = $numerical_value;
        }
        $tagEntity = $this->newEntity($data);
        if ($this->save($tagEntity)) {
            return $tagEntity->id;
        } else {
            return false;
        }
    }

    /**
     * @param string $namespace
     * @param bool $containTagConnectors
     * @return array Uppercase tag name in key
     */
    public function getTagsForNamespace($namespace, $containTagConnectors = true)
    {
        $tag_params = [
            'recursive' => -1,
            'conditions' => ['LOWER(name) LIKE' => strtolower($namespace) . '%'],
        ];
        if ($containTagConnectors) {
            $tag_params['contain'] = ['EventTag', 'AttributeTag'];
        }
        $tags_temp = $this->find('all', $tag_params);
        $tags = [];
        foreach ($tags_temp as $temp) {
            $tags[strtoupper($temp['Tag']['name'])] = $temp;
        }
        return $tags;
    }

    public function getTagsByName($tag_names, $containTagConnectors = true)
    {
        if (empty($tag_names)) {
            return [];
        }

        $tag_params = [
            'recursive' => -1,
            'conditions' => ['name IN' => $tag_names]
        ];
        if ($containTagConnectors) {
            $tag_params['contain'] = ['EventTags', 'AttributeTags'];
        }
        $tags_temp = $this->find('all', $tag_params);
        $tags = [];
        foreach ($tags_temp as $temp) {
            $tags[mb_strtolower($temp['Tag']['name'])] = $temp;
        }
        return $tags;
    }

    public function disableTags($tags)
    {
        foreach ($tags as $k => $v) {
            $tags[$k]['hide_tag'] = 1;
        }
        return $this->saveMany($tags);
    }
}
