<?php

namespace App\Model\Entity;

use Cake\ORM\Entity;

class AppModel extends Entity
{
    const BROTLI_HEADER = "\xce\xb2\xcf\x81";
    const BROTLI_MIN_LENGTH = 200;

    public const ACTION_ADD = 'add',
        ACTION_EDIT = 'edit',
        ACTION_SOFT_DELETE = 'soft_delete',
        ACTION_DELETE = 'delete',
        ACTION_UNDELETE = 'undelete',
        ACTION_TAG = 'tag',
        ACTION_TAG_LOCAL = 'tag_local',
        ACTION_REMOVE_TAG = 'remove_tag',
        ACTION_REMOVE_TAG_LOCAL = 'remove_local_tag',
        ACTION_LOGIN = 'login',
        ACTION_LOGIN_FAIL = 'login_fail',
        ACTION_LOGOUT = 'logout';


    public function getConstant($name)
    {
        return constant('self::' . $name);
    }

    public function getAccessibleFieldForNew(): array
    {
        return $this->_accessibleOnNew ?? [];
    }

    public function rearrangeForAPI(): void
    {
    }

    public function rearrangeMetaFields(): void
    {
        $this->meta_fields = [];
        foreach ($this->MetaTemplates as $template) {
            foreach ($template['meta_template_fields'] as $field) {
                if ($field['counter'] > 0) {
                    foreach ($field['metaFields'] as $metaField) {
                        if (!empty($this->meta_fields[$template['name']][$field['field']])) {
                            if (!is_array($this->meta_fields[$template['name']][$field['field']])) {
                                $this->meta_fields[$template['name']][$field['field']] = [$this->meta_fields[$template['name']][$field['field']]];
                            }
                            $this->meta_fields[$template['name']][$field['field']][] = $metaField['value'];
                        } else {
                            $this->meta_fields[$template['name']][$field['field']] = $metaField['value'];
                        }
                    }
                }
            }
        }
    }

    public function rearrangeTags(array $tags): array
    {
        foreach ($tags as &$tag) {
            $tag = [
                'id' => $tag['id'],
                'name' => $tag['name'],
                'colour' => $tag['colour']
            ];
        }
        return $tags;
    }

    public function rearrangeAlignments(array $alignments): array
    {
        $rearrangedAlignments = [];
        $validAlignmentTypes = ['individual', 'organisation'];
        $alignmentDataToKeep = [
            'individual' => [
                'id',
                'email'
            ],
            'organisation' => [
                'id',
                'uuid',
                'name'
            ]
        ];
        foreach ($alignments as $alignment) {
            foreach (array_keys($alignmentDataToKeep) as $type) {
                if (isset($alignment[$type])) {
                    $alignment[$type]['type'] = $alignment['type'];
                    $temp = [];
                    foreach ($alignmentDataToKeep[$type] as $field) {
                        $temp[$field] = $alignment[$type][$field];
                    }
                    $rearrangedAlignments[$type][] = $temp;
                }
            }
        }
        return $rearrangedAlignments;
    }

    public function rearrangeSimplify(array $typesToRearrange): void
    {
        if (in_array('organisation', $typesToRearrange) && isset($this->organisation)) {
            $this->organisation = [
                'id' => $this->organisation['id'],
                'name' => $this->organisation['name'],
                'uuid' => $this->organisation['uuid']
            ];
        }
        if (in_array('individual', $typesToRearrange) && isset($this->individual)) {
            $this->individual = [
                'id' => $this->individual['id'],
                'email' => $this->individual['email'],
                'uuid' => $this->individual['uuid']
            ];
        }
    }
}
