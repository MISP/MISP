<?php
App::uses('AppModel', 'Model');
class Community extends AppModel
{
    public $useTable = false;

    /**
     * @param string $context
     * @param string|null $value
     * @return array
     */
    public function getCommunityList($context, $value)
    {
        try {
            $community_list = FileAccessTool::readJsonFromFile(APP . 'files/community-metadata/defaults.json');
        } catch (Exception $e) {
            throw new NotFoundException(__('Default community list not in the expected format.'));
        }

        $fieldsToCheck = ['name', 'uuid', 'description', 'url', 'sector', 'nationality', 'type', 'org_uuid', 'org_name'];
        foreach ($community_list as $k => $v) {
            if ($v['misp_project_vetted'] === ($context === 'vetted')) {
                $community_list[$k]['id'] = $k + 1;
                $community_list[$k]['Org'] = array('uuid' => $v['org_uuid'], 'name' => $v['org_name']);
            } else {
                unset($community_list[$k]);
                continue;
            }
            if (!empty($value)) {
                $value = mb_strtolower($value);
                $found = false;
                foreach ($fieldsToCheck as $field) {
                    if (strpos(mb_strtolower($v[$field]), $value) !== false) {
                        $found = true;
                        break;
                    }
                }
                if (!$found) {
                    unset($community_list[$k]);
                }
            }
        }
        return array_values($community_list);
    }

    /**
     * @param int|string $id Community ID or UUID
     * @return array
     */
    public function getCommunity($id)
    {
        try {
            $community_list = FileAccessTool::readJsonFromFile(APP . 'files/community-metadata/defaults.json');
        } catch (Exception $e) {
            throw new NotFoundException(__('Default community list not in the expected format.'));
        }

        foreach ($community_list as $k => $v) {
            $community_list[$k]['id'] = $k + 1;
            $community_list[$k]['Org'] = array('uuid' => $v['org_uuid'], 'name' => $v['org_name']);
        }

        $lookupField = Validation::uuid($id) ? 'uuid' : 'id';
        foreach ($community_list as $s) {
            if ($s[$lookupField === 'uuid' ? 'uuid' : 'id'] == $id) {
                return $s;
            }
        }
        throw new NotFoundException(__('Community not found.'));
    }
}
