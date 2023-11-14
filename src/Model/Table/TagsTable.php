<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use Cake\Core\Configure;

class TagsTable extends AppTable
{
    /**
     * @param array $tag
     * @param array $user
     * @param bool $force
     * @return false|int
     * @throws Exception
     */
    public function captureTag(array $tag, array $user, $force = false)
    {
        $existingTag = $this->find('all', array(
            'recursive' => -1,
            'conditions' => array('LOWER(name)' => mb_strtolower($tag['name'])),
            'fields' => ['id', 'org_id', 'user_id'],
            'callbacks' => false,
        ))->first();
        if (empty($existingTag)) {
            if ($force || $user['Role']['perm_tag_editor']) {
                if (empty($tag['colour'])) {
                    $tag['colour'] = $this->tagColor($tag['name']);
                }
                $tagEntity = $this->newEntity(array(
                    'name' => $tag['name'],
                    'colour' => $tag['colour'],
                    'exportable' => isset($tag['exportable']) ? $tag['exportable'] : 1,
                    'local_only' => $tag['local_only'] ?? 0,
                    'org_id' => 0,
                    'user_id' => 0,
                    'hide_tag' => Configure::read('MISP.incoming_tags_disabled_by_default') ? 1 : 0
                ));
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
                    $existingTag['Tag']['org_id'] != 0 &&
                    $existingTag['Tag']['org_id'] != $user['org_id']
                ) ||
                (
                    $existingTag['Tag']['user_id'] != 0 &&
                    $existingTag['Tag']['user_id'] != $user['id']
                )
            )
        ) {
            return false;
        }
        return $existingTag['Tag']['id'];
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
        $data = array(
            'name' => $name,
            'colour' => $colour,
            'exportable' => 1,
        );
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
}
