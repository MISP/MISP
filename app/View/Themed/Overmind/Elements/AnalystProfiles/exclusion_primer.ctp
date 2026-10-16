<?php
/**
 * The Exclusions pane's primer: what leaving evidence out does, and
 * what each "applies to" tag means.
 *
 * @var array $primer `layers` from ValueExclusionTool::layers()
 */
?>
<div class="sig-pop-body" aria-labelledby="sig-pop-title-exclusions">
    <div class="sig-pop-head">
        <div class="sig-pop-titles">
            <p class="sig-pop-title" id="sig-pop-title-exclusions"><?=
                h($primer['label']) ?></p>
            <p class="sig-pop-sub"><?= h(__('Read this once; each'
                . ' exclusion\'s own "How it works" says the rest.')) ?></p>
        </div>
        <button type="button" class="sig-pop-close" data-ap-help-close
                aria-label="<?= h(__('Close')) ?>">
            <i class="fa-solid fa-xmark" aria-hidden="true"></i>
        </button>
    </div>
    <div class="sig-pop-grid">
        <div class="sig-pop-col" data-col="a">
            <h4><?= h(__('The evidence changes, not its worth')) ?></h4>
            <p><?= h(__('An exclusion takes evidence away before any signal'
                . ' reads the record, so every signal sees the same,'
                . ' smaller set. The points stay what they are; the counts'
                . ' under them shrink.')) ?></p>
            <h4><?= h(__('Nothing is hidden')) ?></h4>
            <p><?= h(__('What an exclusion removed is listed in the'
                . ' assessment under not counted, so a reader sees what was'
                . ' left out and why.')) ?></p>
            <h4><?= h(__('An emptied set stays silent')) ?></h4>
            <p><?= h(__('When an exclusion removed everything a signal'
                . ' reads, the signal does not score the gap: a value whose'
                . ' only sightings were self-sightings is not a value'
                . ' nobody sighted.')) ?></p>
        </div>
        <div class="sig-pop-col" data-col="b">
            <h4><?= h(__('What "applies to" says')) ?></h4>
            <dl class="sig-pop-sets">
                <?php foreach ($primer['layers'] as $layer): ?>
                    <dt><span class="sig-tag"><b><?= h($layer['label'])
                        ?></b></span></dt>
                    <dd><?= h($layer['title']) ?></dd>
                <?php endforeach; ?>
            </dl>
        </div>
        <div class="sig-pop-col" data-col="c">
            <h4><?= h(__('Try it')) ?></h4>
            <ul class="sig-pop-recipes">
                <li>
                    <span class="want"><?= h(__('See what an exclusion'
                        . ' removes')) ?></span>
                    <span class="do"><?= h(__('Put a value on the bench and'
                        . ' tick it: the signals that read what it removed'
                        . ' move in the ledger on the right.')) ?></span>
                </li>
                <li>
                    <span class="want"><?= h(__('Make some evidence count'
                        . ' less, not nothing')) ?></span>
                    <span class="do"><?= h(__('Lower its signal\'s points'
                        . ' under Signals instead. An exclusion is all or'
                        . ' nothing.')) ?></span>
                </li>
                <li>
                    <span class="want"><?= h(__('Count it again')) ?></span>
                    <span class="do"><?= h(__('Untick the exclusion. Its'
                        . ' settings are kept.')) ?></span>
                </li>
            </ul>
        </div>
    </div>
</div>
