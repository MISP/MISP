<?php
/**
 * The Assessment tab for a value whose signals agree (and for a contested
 * one with no separable cases): the reading and its three answers in one
 * header, then one card per answer in the same order — who says it
 * (stance), how the signal strength was built, how long the reading holds.
 * What would change it and what is not counted are in the rail, from
 * value_verdict_aside.
 *
 * Lazily loaded into `.ajax-tab-content` from
 * ValuesController::viewVerdict.
 *
 * @var array $valueIntelligence
 */
$verdict = $valueIntelligence['verdict'];
?>
<?= $this->element('Values/View/value_verdict_head', array('verdict' => $verdict)) ?>
<?= $this->element('Values/View/value_verdict_voices', array('verdict' => $verdict)) ?>
<?= $this->element('Values/View/value_verdict_ledger', array('verdict' => $verdict)) ?>
<?= $this->element('Values/View/value_verdict_relevance', array('verdict' => $verdict)) ?>
