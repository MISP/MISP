<?php
/**
 * One section of a profile as the card of its tab.
 *
 * @var array $section
 * @var bool $editable
 * @var array $readings AnalystProfileFormTool::benchReadings()
 * @var string|null $benchValue
 */
?>
<div class="card ap-tab-card">
    <?= $this->element('AnalystProfiles/section', array(
        'section' => $section,
        'editable' => $editable,
        'open' => true,
        'ledger' => $readings['ledger'],
        'benchValue' => $benchValue,
        'marks' => $readings['marks'],
        'runway' => $readings['runway'],
        'lean' => $readings['lean'],
        'compact' => true,
    )) ?>
</div>
