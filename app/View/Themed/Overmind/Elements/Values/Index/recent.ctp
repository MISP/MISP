<?php
/**
 * Carried over — the values this reader last opened.
 *
 * The one block on this page whose rows are neither the reader's paste
 * nor an aggregate over `attributes`: it reads ten strings out of one
 * `user_settings` row that this reader put there by opening them
 * (`value-index.md` §7.4).
 *
 * **Yours alone, and it says so.** D27 refuses to name who ran an
 * enrichment because naming the runner tells the organisation which
 * colleague is looking at which value; a recently-viewed list anybody
 * else could read is that disclosure with a different label. The
 * sentence beside its count is not reassurance — it is the reason a
 * reader can use the block without thinking about who is watching.
 *
 * **No lean on an entry.** Ten assessments is ten engine runs spent
 * before the reader has pasted anything, on a block nobody has asked a
 * question of yet (`02a-contract.md` §12.7). The hover card answers
 * for the value under the cursor, at the moment there is one, and
 * costs nothing until then — so each entry is a hover trigger where the
 * instance has the card on, and a plain link where it does not.
 *
 * An empty one is a sentence in the future tense rather than an empty
 * list, so a new install does not read as broken.
 *
 * @var array<array{value: string, at: int}> $recent Newest first
 */
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');
/*
 * `CakeTime` and not `$this->Time`. MISP replaces CakePHP's
 * `TimeHelper` wholesale with a two-method helper of its own — `time()`
 * and `date()` — so `$this->Time->timeAgoInWords()` reaches
 * `Helper::__call`, returns the empty string, and renders a chip with a
 * blank where the age goes. Nothing throws and the page looks finished.
 */
App::uses('CakeTime', 'Utility');

$hoverCard = (bool)Configure::read('MISP.value_hover_card');
?>
<section class="vi-recent" aria-labelledby="vi-recent-title">
    <div class="ifp-row">
        <span class="ifp-count" id="vi-recent-title"><?= sprintf(
            h(__('%s recently opened')),
            '<b>' . h(count($recent)) . '</b>'
        ) ?></span>
        <span class="vi-recent__mine"><i class="fas fa-lock" aria-hidden="true"></i> <?= h(__('Only you can see this list.')) ?></span>
    </div>
    <div class="card shadow-sm mb-4">
        <div class="card-body p-0">
<?php if (empty($recent)): ?>
            <p class="vi-recent__lead"><?= h(__('Values you open will be listed here.')) ?></p>
<?php else: ?>
            <table class="table table-hover align-middle mb-0 ix-table vi-recent__table">
                <thead>
                    <tr>
                        <th scope="col"><?= h(__('Value')) ?></th>
                        <th scope="col" class="vi-recent__at"><?= h(__('Opened')) ?></th>
                    </tr>
                </thead>
                <tbody>
<?php   foreach ($recent as $entry): ?>
                    <tr>
                        <td>
                            <div class="attr-value">
                                <div class="attr-value-line">
                                    <p class="fw-semibold mb-0"><a class="vi-recent__value"
                                       href="<?= h($this->Html->url(array(
                                           'controller' => 'values',
                                           'action' => 'view',
                                           ValueUrlTool::address($entry['value']),
                                       ))) ?>"><?= $this->element('Attributes/value_display', array(
                                           'attribute' => array('value' => $entry['value'], 'type' => ''),
                                           'hoverValue' => $hoverCard ? ValueUrlTool::address($entry['value']) : null,
                                           'cap' => 128,
                                       )) ?></a></p>
                                </div>
                            </div>
                        </td>
                        <td class="vi-recent__at" title="<?= h(date('Y-m-d H:i', $entry['at'])) ?>"><?= h(
                            CakeTime::timeAgoInWords($entry['at'], array(
                                /*
                                 * One unit rather than two past a day: the
                                 * hour is not what a reader scanning this
                                 * list is asking about.
                                 */
                                'accuracy' => array('day' => 'day'),
                            ))
                        ) ?></td>
                    </tr>
<?php   endforeach; ?>
                </tbody>
            </table>
<?php endif; ?>
        </div>
    </div>
</section>
