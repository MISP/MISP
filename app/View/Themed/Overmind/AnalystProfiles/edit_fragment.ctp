<?php
/**
 * One section with its inputs, for the view to take a parameter from
 * (analyst-profile-settings.js). It is never shown as it stands.
 *
 * @var array $sections
 * @var array $bench
 * @var bool $editable
 * @var string|null $open_section
 */
App::uses('AnalystProfileFormTool', 'Tools/AnalystProfile');

$readings = AnalystProfileFormTool::benchReadings($bench['detail']);
$benched = !empty($bench['values']) ? $bench['values'][0] : null;
foreach ($sections as $id => $section) {
    if ($open_section !== null && $id !== $open_section) {
        continue;
    }
    echo $this->element('AnalystProfiles/section', array(
        'section' => $section,
        'editable' => $editable,
        'open' => true,
        'ledger' => $readings['ledger'],
        'benchValue' => $benched,
        'marks' => $readings['marks'],
        'runway' => $readings['runway'],
        'lean' => $readings['lean'],
        'compact' => true,
    ));
}
