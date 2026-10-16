<?php
/**
 * What the box resolved to, when it did not land on a profile.
 *
 * Three answers, none of them an error page. A value nothing here
 * records is the answer to the question the reader asked
 * (`value-index.md` §7.1, V3), so it is stated plainly and the profile
 * — which says the same thing with the tabs to prove it — is offered
 * anyway. A hit never reaches this element: it is a `303` to the
 * profile, and the profile is the page that says everything else.
 *
 * The third is the refusal over the cap, which says the count rather
 * than truncating to it: a page that assessed the first hundred of
 * three hundred and forty would have dropped the two hundred and
 * forty the reader would never think to check.
 *
 * It carries its own padding because `triage()` renders it as the
 * whole response when a paste is refused, and a fragment that relies
 * on a wrapper the page draws arrives without one.
 *
 * **Nothing here distinguishes a value the reader may not see from a
 * value nobody recorded** (§4.2, §8 G3). There is one *absent* answer,
 * one wording, and it is drawn from `recorded === false` alone — the
 * probe behind it is viewer-scoped, so this element is never told
 * which of the two it is looking at and cannot leak what it does not
 * know.
 *
 * @var array $resolution `kind`, and what that kind carries
 */
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');
App::uses('ValueInputTool', 'Tools/ValueIntelligence');

$kind = $resolution['kind'];
$profileUrl = function ($value) {
    return $this->Html->url(array(
        'controller' => 'values',
        'action' => 'view',
        ValueUrlTool::encode($value),
    ));
};
?>
<div class="vi-answerwrap">
<div class="vi-answer">
<?php if ($kind === 'absent'): ?>
    <p class="vi-said"><?= h($resolution['value']) ?></p>
<?php   $changed = $resolution['changed']; ?>
<?php   if (in_array(ValueInputTool::REFANGED, $changed, true)): ?>
    <p class="vi-note"><?= h(__(
        'Your input was refanged before the lookup, as MISP stores'
        . ' values refanged. The box above still shows what you'
        . ' pasted.'
    )) ?></p>
<?php   elseif (in_array(ValueInputTool::UNQUOTED, $changed, true)): ?>
    <p class="vi-note"><?= h(__(
        'The surrounding quotes were removed before the lookup.'
    )) ?></p>
<?php   endif; ?>
<?php   if ($resolution['suggestion'] === null): ?>
    <p><?= h(__(
        'Nothing you can see records this value, so there is nothing'
        . ' to assess.'
    )) ?></p>
    <div class="vi-offer">
        <a class="vi-btn" href="<?= h($profileUrl($resolution['value'])) ?>">
            <?= h(__('Open the Value Intelligence anyway')) ?>
        </a>
        <span class="vi-mark"><?= h(__(
            'It will show the same result, tab by tab.'
        )) ?></span>
    </div>
<?php   else: ?>
    <p><?= sprintf(
        h(__('Not recorded as typed. Recorded as %s.')),
        '<b class="vi-said-inline">' . h($resolution['suggestion']) . '</b>'
    ) ?></p>
    <div class="vi-offer">
        <a class="vi-btn vi-btn--lead"
           href="<?= h($profileUrl($resolution['suggestion'])) ?>">
            <?= h(sprintf(__('Open %s'), $resolution['suggestion'])) ?>
        </a>
        <a class="vi-btn vi-btn--quiet"
           href="<?= h($profileUrl($resolution['value'])) ?>">
            <?= h(sprintf(__('Open %s anyway'), $resolution['value'])) ?>
        </a>
    </div>
    <p class="vi-quiet"><?= h(__(
        'MISP shows the two spellings together, but an accent can make a'
        . ' different domain. Only you can tell which one your source'
        . ' meant.'
    )) ?></p>
<?php   endif; ?>
<?php elseif ($kind === 'over'): ?>
    <p class="vi-refusal"><?= h(sprintf(
        __('You pasted %1$d values, but the limit is %2$d at a time.'),
        $resolution['count'],
        $resolution['cap']
    )) ?></p>
    <p class="vi-quiet"><?= h(sprintf(
        __('Nothing was looked up, and your paste is still in the box.'
            . ' Trim it to %1$d values, or split it into %2$d'
            . ' batches.'),
        $resolution['cap'],
        $resolution['goes']
    )) ?></p>
<?php else: ?>
<?php
    /*
     * An empty box and a page of prose the extractor found nothing in
     * are the same shape and not the same answer. The first is *you
     * pasted nothing*; the second is *this found nothing in what you
     * pasted*, which is a claim about the reader's text and has to be
     * offered a way back — the extractor can only find what MISP is
     * able to type (`value-index.md` §11.2).
     */
    $mode = isset($resolution['mode'])
        ? $resolution['mode']
        : ValueInputTool::MODE_LINES;
?>
<?php   if ($mode === ValueInputTool::MODE_EXTRACT
        && !empty($resolution['lines'])): ?>
    <p><?= h(sprintf(__n('No value found in that line.',
        'No value found in those %d lines.',
        $resolution['lines']), $resolution['lines'])) ?></p>
    <p class="vi-quiet"><?= h(__(
        'Extraction only picks up values it can give an attribute'
        . ' type, so a mutex, a CPE string or a user agent is missed.'
        . ' Your paste is still in the box.'
    )) ?></p>
    <?= $this->element('Values/Index/reread', array(
        'extract' => 0,
        'label' => __('Look up each line instead'),
        'note' => __('To look up every line exactly as pasted:'),
    )) ?>
<?php   else: ?>
    <p><?= h(__('The box is empty. Paste a value to look it up.')) ?></p>
<?php   endif; ?>
<?php endif; ?>
</div>
</div>
