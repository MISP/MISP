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
                    $this->Log->createLogEntry($user, 'attachTags', 'EventReportTag', 0, __('Could not attach %s tag %s', (empty($local) ? 'global' : 'local'), $tagId), __('event-report (%s)', $eventReportID));
                } else {
                    $allSaveResult['successes'] += 1;
                }
            }
        }
        return $allSaveResult;
    }
}
