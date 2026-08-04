<?php
App::uses('AppModel', 'Model');

/**
 * @property Tag $Tag
 */
class EventReportTag extends AppModel
{
    public $useTable = 'event_report_tags';
    public $actsAs = ['AuditLog', 'Containable'];

    public $validate = [
        'event_report_id' => [
            'valueNotEmpty' => [
                'rule' => ['valueNotEmpty'],
            ],
        ],
        'tag_id' => [
            'valueNotEmpty' => [
                'rule' => ['valueNotEmpty'],
            ],
        ],
    ];

    public $belongsTo = [
        'EventReport' => [
            'className' => 'EventReport',
        ],
        'Tag' => [
            'className' => 'Tag',
        ],
    ];

    /**
     * attachTags
     *
     * @param  array $user
     * @param  int   $eventReportID
     * @param  array $tags list of tag names to be saved
     * @param  bool  $capture
     * @return bool
     */
    public function attachTags(array $user, $eventReportID, array $tag_id_list, $local = false)
    {
        $allSaveResult = [
            'fails' => 0,
            'successes' => 0,
        ];
        foreach ($tag_id_list as $tagId) {
            $existingAssociation = $this->find('first', [
                'recursive' => -1,
                'conditions' => [
                    'tag_id' => $tagId,
                    'event_report_id' => $eventReportID,
                    'local' => $local,
                ]
            ]);
            if (empty($existingAssociation) && $tagId != -1) {
                $this->create();
                $saveResult = $this->save(['event_report_id' => $eventReportID, 'tag_id' => $tagId, 'local' => $local]);
                if (!$saveResult) {
                    $allSaveResult['fails'] += 1;
                    $this->loadLog()->createLogEntry($user, 'attachTags', 'EventReportTag', 0, __('Could not attach %s tag %s', (empty($local) ? 'global' : 'local'), $tagId), __('event-report (%s)', $eventReportID));
                } else {
                    $allSaveResult['successes'] += 1;
                }
            }
        }
        return $allSaveResult;
    }

    // This function help mirroring the tags at event-report level. It will delete tags that are not present on the remote report
    public function pruneOutdatedTagsFromSync($newerTags, $originalGlobalTags)
    {
        $newerTagsName = [];
        foreach ($newerTags as $tag) {
            $newerTagsName[] = strtolower($tag['name']);
        }
        foreach ($originalGlobalTags as $k => $reportTag) {
            if (!in_array(strtolower($reportTag['Tag']['name']), $newerTagsName)) {
                $this->softDelete($reportTag['EventReportTag']['id']);
            }
        }
    }

    public function captureEventReportTags($user, $event_report_id, $eventReportTags)
    {
        foreach ($eventReportTags as $tag) {
            $tag_id = $this->Tag->captureTag($tag, $user);
            if ($tag_id) {
                $tag['id'] = $tag_id;
                $isLocal = !empty($tag['local']) ? $tag['local'] : false;
                $this->handleEventReportTag($user, $event_report_id, $tag_id, $isLocal);
            } else {
                // If we couldn't attach the tag it is most likely because we couldn't create it - which could have many reasons
                // However, if a tag couldn't be added, it could also be that the user is a tagger but not a tag editor
                // In which case if no matching tag is found, no tag ID is returned. Logging these is pointless as it is the correct behaviour.
                if ($user['Role']['perm_tag_editor']) {
                    $this->loadLog()->createLogEntry($user, 'capture', 'EventReportTag', $event_report_id, "Failed create or attach Tag {$tag['name']} to the event.");
                }
            }
        }
    }

    public function handleEventReportTag($user, $event_report_id, $tag_id, $local=false)
    {
        if (empty($tag['deleted'])) {
            $result = $this->attachTags($user, $event_report_id, [$tag_id], $local);
        } else {
            $result = $this->detachTagFromEventReport($event_report_id, $tag_id, $local);
        }
        return $result;
    }

    public function detachTagFromEventReport($event_report_id, $tag_id, $local=false): bool
    {
        $conditions = [
            'tag_id' => $tag_id,
            'event_report_id' => $event_report_id,
        ];
        if (!is_null($local)) {
            $conditions['local'] = !empty($local);
        }
        $existingAssociation = $this->find('first', [
            'recursive' => -1,
            'fields' => ['id'],
            'conditions' => $conditions,
        ]);

        if ($existingAssociation) {
            $result = $this->softDelete($existingAssociation['EventTag']['id']);
            if ($result) {
                return true;
            }
        }
        return false;
    }

    public function softDelete($id)
    {
        $this->delete($id);
    }
}
