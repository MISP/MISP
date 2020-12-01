<?php
App::uses('AppModel', 'Model');
class Community extends AppModel
{
    public $useTable = false;

    public $recursive = -1;

    public $actsAs = array(
            'Containable',
    );

    public $validate = array(
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        return true;
    }

    public function getCommunityList($context, $value)
    {
        $community_file = new File(APP . 'files/community-metadata/defaults.json');
        if (!$community_file->exists()) {
            throw new NotFoundException(__('Default community list not found.'));
        }
        $community_list = $community_file->read();
        if (empty($community_list)) {
            throw new NotFoundException(__('Default community list empty.'));
        }
        try {
            $community_list = json_decode($community_list, true);
        } catch (Exception $e) {
            throw new NotFoundException(__('Default community list not in the expected format.'));
        }
        $fieldsToCheck = array('name', 'uuid', 'description', 'url', 'sector', 'nationality', 'type', 'org_uuid', 'org_name');
        foreach ($community_list as $k => $v) {
            if ($v['misp_project_vetted'] === ($context === 'vetted')) {
                $community_list[$k]['id'] = $k + 1;
                $community_list[$k]['Org'] = array('uuid' => $v['org_uuid'], 'name' => $v['org_name']);
            } else {
                unset($community_list[$k]);
                continue;
            }
            if (!empty($value)) {
                $found = false;
                foreach ($fieldsToCheck as $field) {
                    if (strpos(strtolower($v[$field]), $value) !== false) {
                        $found = true;
                        continue;
                    }
                }
                if (!$found) {
                    unset($community_list[$k]);
                }
            }
        }
        $community_list = array_values($community_list);
        return $community_list;
    }

    public function getCommunity($id)
    {
        $community_file = new File(APP . 'files/community-metadata/defaults.json');
        if (!$community_file->exists()) {
            throw new NotFoundException(__('Default community list not found.'));
        }
        $community_list = $community_file->read();
        if (empty($community_list)) {
            throw new NotFoundException(__('Default community list empty.'));
        }
        try {
            $community_list = json_decode($community_list, true);
        } catch (Exception $e) {
            throw new NotFoundException(__('Default community list not in the expected format.'));
        }
        foreach ($community_list as $k => $v) {
            $community_list[$k]['id'] = $k + 1;
            $community_list[$k]['Org'] = array('uuid' => $v['org_uuid'], 'name' => $v['org_name']);
        }
        $community = false;
        $lookupField = 'id';
        if (Validation::uuid($id)) {
            $lookupField = 'uuid';
        }
        foreach ($community_list as $s) {
            if ($s[$lookupField === 'uuid' ? 'uuid' : 'id'] === $id) {
                $community = $s;
            }
        }
        if (empty($community)) {
            throw new NotFoundException(__('Community not found.'));
        }
        return $community;
    }
}
