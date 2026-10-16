<?php
/**
 * The conditions strip — under what rules this reader's session is
 * worked.
 *
 * It sits above the box rather than below the answers, because what it
 * says is true of every answer the box will give and a reader meets it
 * before the first one (`value-index/02b-proposal-c.html`, state 1).
 *
 * **Phase 7's occupant is the profile in force.** An assessment is
 * what a set of thresholds made of the record, so *whose thresholds*
 * is the first thing a reader needs in order to read a band they
 * disagree with. The name says which document, the revision says which
 * version of it — a band that moved overnight moved because the value
 * did or because the profile did, and nothing else on the page
 * separates those two — and the scope says whose pages an edit would
 * move, which is the half that can be acted on (D3).
 *
 * **The link goes where the reader may actually go.** `editable` is
 * `AnalystProfilesController::edit()`'s own predicate rather than a
 * guess from the scope, so the offer and the action cannot disagree: a
 * site admin on the instance default is offered the editor they may
 * use, and an analyst on their organisation's profile without
 * `perm_admin` is offered the page that shows the thresholds instead
 * of a link that 403s (§7.5).
 *
 * **No profile in force is a state, not a failure.** A site admin can
 * disable the default, and every assessment on the instance then
 * carries a lean and no signal strength, because no signal can fire to band
 * one. That is worth saying plainly; it is the one condition on this
 * page a reader could otherwise mistake for a broken engine.
 *
 * **Phase 8's occupant is the method note**, last in the strip and
 * carrying its own block. The sentence above says whose thresholds
 * decided an assessment; the note says what an assessment is at all,
 * and a reader who needs the second needs it before the first means
 * anything. It is a `<details>`, so it costs one quiet line until it
 * is asked for.
 *
 * **The strip holds conditions and not measurements.** Phase 9's
 * enrichment store started here and moved to a tile at the foot: what
 * the strip says is a rule the reader works under and cannot change by
 * working, while a count moves as the organisation enriches. A figure
 * that moves, set as running prose between two rules, is a figure
 * nobody reads twice.
 *
 * @var array{id: int|null, name: string, scope: string,
 *            revision: int, editable: bool}|null $inForce
 */
if ($inForce === null) {
    $line = h(__(
        'No analyst profile is active, so assessments show a lean but'
        . ' no signal strength until a site admin enables one.'
    ));
    $link = null;
} else {
    /*
     * The name and the revision are one token: they name a document
     * and a version of it, and a line break between them would read
     * as two facts.
     */
    $named = '<b>' . h($inForce['name']) . '</b> '
        . '<span class="vi-rev">'
        . h(sprintf(__('rev %d'), $inForce['revision']))
        . '</span>';
    switch ($inForce['scope']) {
        case 'user':
            $line = sprintf(
                h(__('Assessments use %s, your personal analyst profile.')),
                $named
            );
            break;
        case 'org':
            $line = sprintf(
                h(__(
                    'Assessments use %s, your organisation\'s analyst'
                    . ' profile.'
                )),
                $named
            );
            break;
        case 'shared':
            $line = sprintf(
                h(__('Assessments use %s, a shared analyst profile.')),
                $named
            );
            break;
        default:
            $line = sprintf(
                h(__(
                    'Assessments use %s, the instance default. Only a'
                    . ' site admin can change it.'
                )),
                $named
            );
    }
    /*
     * A profile with no id has no page. `resolveFor()` never returns
     * one, and the guard is here so that the day something hands the
     * engine a profile assembled in memory the strip loses a link
     * rather than drawing one to `/analystProfiles/view/`.
     */
    $link = $inForce['id'] === null ? null : $this->Html->link(
        $inForce['editable']
            ? __('Edit thresholds')
            : __('View thresholds'),
        array(
            'controller' => 'analystProfiles',
            'action' => $inForce['editable'] ? 'edit' : 'view',
            $inForce['id'],
        ),
        array('class' => 'vi-condlink')
    );
}
?>
<div class="vi-cond">
    <span><?= $line ?><?php if ($link !== null): ?> <?= $link ?><?php endif; ?></span>
    <?= $this->element('Values/Index/method') ?>
</div>
