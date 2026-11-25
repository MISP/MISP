<?php

/**
 * The fields a dialog asks for a new event, checked and shaped as
 * Event::_add() takes them. The event is always created unpublished.
 */
class NewEventFormTool
{
    /**
     * @param array $user
     * @param mixed $event `info`, `date` (Y-m-d), `distribution`,
     *   `sharing_group_id`, `threat_level_id`, `analysis`
     * @param Event $eventModel
     * @return array [array|null $fields, array $errors field => message]
     */
    public static function fields(array $user, $event, $eventModel)
    {
        $event = is_array($event) ? $event : [];
        $errors = [];
        $info = trim((string)($event['info'] ?? ''));
        if ($info === '') {
            $errors['info'] = __('Please provide a name for the event.');
        } elseif (strlen($info) > 65535) {
            $errors['info'] = __('Event info is too long.');
        }
        $date = (string)($event['date'] ?? '');
        $parsed = DateTime::createFromFormat('!Y-m-d', $date);
        if (!$parsed || $parsed->format('Y-m-d') !== $date) {
            $errors['date'] = __('Enter the event date.');
        }
        $distribution = (int)($event['distribution'] ?? 0);
        $sharingGroupId = null;
        if (!array_key_exists($distribution, $eventModel->distributionLevels)) {
            $errors['distribution'] = __('Pick a distribution.');
        } elseif ($distribution === 4) {
            $sharingGroupId = (int)($event['sharing_group_id'] ?? 0);
            if (!$eventModel->SharingGroup->canUse($user, $sharingGroupId)) {
                $errors['sharing_group_id'] = __('Pick a sharing group you may use.');
            }
        }
        $threatLevel = (int)($event['threat_level_id'] ?? 0);
        if (!$eventModel->ThreatLevel->hasAny(['ThreatLevel.id' => $threatLevel])) {
            $errors['threat_level_id'] = __('Pick a threat level.');
        }
        $analysis = (int)($event['analysis'] ?? -1);
        if (!array_key_exists($analysis, $eventModel->analysisLevels)) {
            $errors['analysis'] = __('Pick an analysis level.');
        }
        if (!empty($errors)) {
            return [null, $errors];
        }
        $fields = [
            'info' => $info,
            'date' => $date,
            'distribution' => $distribution,
            'threat_level_id' => $threatLevel,
            'analysis' => $analysis,
            'published' => 0,
        ];
        if ($sharingGroupId !== null) {
            $fields['sharing_group_id'] = $sharingGroupId;
        }
        return [$fields, []];
    }
}
