<?php

App::uses('AppModel', 'Model');

class TagCollection extends AppModel
{
    public $useTable = 'tag_collections';

    public $displayField = 'name';

    public $actsAs = array(
            'Trim',
            'SysLogLogable.SysLogLogable' => array(
                    'roleModel' => 'Role',
                    'roleKey' => 'role_id',
                    'change' => 'full'
            ),
            'Containable'
    );

    public $hasMany = array(
        'TagCollectionTag' => array(
            'dependent' => true
        )
    );

    public $belongsTo = array(
        'User',
        'Organisation' => array(
            'foreignKey' => 'org_id'
        )
    );

    public $whitelistedItems = false;

    public $validate = array(
        'name' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
            'unique' => array(
                    'rule' => 'isUnique',
                    'message' => 'A similar name already exists.',
            ),
        )
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        // generate UUID if it doesn't exist
        if (empty($this->data['TagCollection']['uuid'])) {
            $this->data['TagCollection']['uuid'] = CakeText::uuid();
        }
        return true;
    }

    public function fetchTagCollection($user, $params = array())
    {
        if (empty($user['Role']['perm_site_admin'])) {
            $params['conditions']['AND'][] = array(
                'OR' => array(
                    'TagCollection.org_id' => $user['org_id'],
                    'TagCollection.all_orgs' => 1
                )
            );
        }
        if (empty($params['contain'])) {
            $params['contain'] = array(
                'Organisation',
                'User',
                'TagCollectionTag' => array('Tag')
            );
        }
        $tagCollections = $this->find('all', $params);
        $tagCollections = $this->cullBlockedTags($user, $tagCollections);
        return $tagCollections;
    }

    public function checkAccess($user, $tagCollection, $accessLevel = 'read')
    {
        if (isset($tagCollection['TagCollection'])) {
            $tagCollection = $tagCollection['TagCollection'];
        }
        if (!empty($user['Role']['perm_site_admin'])) {
            return true;
        }
        if (!$tagCollection['all_orgs'] && $user['org_id'] != $tagCollection['org_id']) {
            return false;
        }
        if ($accessLevel === 'write') {
            if ($tagCollection['org_id'] !== $user['org_id']) {
                return false;
            }
        }
        return true;
    }

    public function cullBlockedTags($user, $tagCollections)
    {
        $single = false;
        if (!isset($tagCollections[0])) {
            $tagCollections = array(0 => $tagCollections);
            $single = true;
        }
        if (empty($user['Role']['perm_site_admin'])) {
            foreach ($tagCollections as $k => $tagCollection) {
                foreach ($tagCollection['TagCollectionTag'] as $k2 => $tagCollectionTag) {
                    if (
                        (!empty($tagCollectionTag['Tag']['org_id']) && $tagCollectionTag['Tag']['org_id'] != $user['org_id']) ||
                        (!empty($tagCollectionTag['Tag']['user_id']) && $tagCollectionTag['Tag']['user_id'] != $user['id']) ||
                        $tagCollectionTag['Tag']['hide_tag']
                    ) {
                        unset($tagCollections[$k]['TagCollectionTag'][$k2]);
                    }
                }
                $tagCollections[$k]['TagCollectionTag'] = array_values($tagCollections[$k]['TagCollectionTag']);
            }
        }
        return $single ? $tagCollections[0] : $tagCollections;
    }

    public function import($collections, $user)
    {
        $results = array('successes' => 0, 'fails' => 0);
        if (empty($collections)) {
            return $results;
        }
        if (isset($collections['TagCollection'])) {
            $collections = array($collections);
        }
        foreach ($collections as $collection) {
            $existingCollection = $this->find('first', array(
                'conditions' => array(
                    'TagCollection.uuid' => $collection['TagCollection']['uuid']
                ),
                'recursive' => -1
            ));
            if (!empty($existingCollection)) {
                continue;
            }
            if (isset($collection['TagCollection']['id'])) {
                unset($collection['TagCollection']['id']);
            }
            $this->create();
            $collection['TagCollection']['user_id'] = $user['id'];
            $collection['TagCollection']['org_id'] = $user['org_id'];
            if (!$this->save($collection)) {
                $results['fails']++;
            } else {
                $results['successes']++;
                if (!empty($collection['TagCollectionTag'])) {
                    foreach ($collection['TagCollectionTag'] as $tct) {
                        $tag_id = $this->TagCollectionTag->Tag->captureTag($tct['Tag'], $user);
                        $this->TagCollectionTag->create();
                        $this->TagCollectionTag->save(array(
                            'tag_collection_id' => $this->id,
                            'tag_id' => $tag_id
                        ));
                    }
                }
                if (!empty($collection['Galaxy'])) {
                    foreach ($collection['Galaxy'] as $galaxy) {
                        foreach ($galaxy['GalaxyCluster'] as $cluster) {
                            $tag_id = $this->TagCollectionTag->Tag->lookupTagIdFromName($cluster['tag_name']);
                            if ($tag_id === -1) {
                                $tag = array(
                                    'name' => $cluster['tag_name']
                                );
                                $tag_id = $this->TagCollectionTag->Tag->captureTag($tag, $user);
                            }
                            $this->TagCollectionTag->create();
                            $this->TagCollectionTag->save(array(
                                'tag_collection_id' => $this->id,
                                'tag_id' => $tag_id
                            ));
                        }
                    }
                }
            }
        }
        return $results;
    }
}
