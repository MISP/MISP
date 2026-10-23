<?php
/**
 * The sharing group popover of the events index (SharingGroupsController::peek()).
 * Opened by events-index-cards.js inside its .dk-pop-float.
 *
 * @var array $peek SharingGroupPeek::build()
 */
App::uses('EventCardTool', 'Tools/EventOverview');

$badge = EventCardTool::distribution(4);
$groupUrl = $baseurl . '/sharing_groups/view/' . (int)$peek['id'];
$members = $peek['members'];
?>
<div class="dk-sg-pop" data-sg-id="<?= (int)$peek['id'] ?>">
    <div class="dk-pop-head dk-sg-head">
        <span class="dk-dist dk-sg-badge" style="<?= h($badge['style']) ?>"><i class="<?= h($badge['icon']) ?>"></i></span>
        <div class="dk-sg-title">
            <b><?= h($peek['name']) ?></b>
            <small><?= $peek['owner']['name'] !== ''
                ? sprintf(h(__('Sharing group · owned by %s')), '<b>' . h($peek['owner']['name']) . '</b>')
                : h(__('Sharing group')) ?></small>
            <?php if ($peek['pills']): ?>
                <span class="dk-sg-pills">
                    <?php foreach ($peek['pills'] as $pill): ?>
                        <span class="dk-sg-pill<?= $pill['warn'] ? ' is-warn' : '' ?>"><i class="<?= h($pill['icon']) ?>"></i><?= h($pill['label']) ?></span>
                    <?php endforeach; ?>
                </span>
            <?php endif; ?>
        </div>
        <button type="button" class="dk-pop-x" data-dk-close aria-label="<?= h(__('Close')) ?>"><i class="fas fa-xmark"></i></button>
    </div>

    <section class="dk-pop-sec">
        <h4><i class="misp-icon misp-icon-organisation misp-simple"></i><?= h(__('Organisations')) ?>
            <?php if ($members !== null && $peek['member_count']): ?><small><?= (int)$peek['member_count'] ?></small><?php endif; ?>
        </h4>
        <?php if ($members === null): ?>
            <p class="dk-sg-p"><?= h(__n('%s member organisation', '%s member organisations', $peek['member_count'], $peek['member_count'])) ?></p>
        <?php else: ?>
            <?php if ($peek['everyone']): ?>
                <p class="dk-sg-p"><?= h(__('Every organisation on this instance')) ?></p>
            <?php elseif (!$members): ?>
                <p class="dk-sg-p is-quiet"><?= h(__('No organisation is a member yet.')) ?></p>
            <?php endif; ?>
            <?php if ($members): ?>
                <ul class="dk-sg-orgs">
                    <?php foreach ($members as $org): ?>
                        <li>
                            <?= $this->EventIndex->orgTile(['id' => $org['id'], 'name' => $org['name'], 'uuid' => $org['uuid']], 20) ?>
                            <span class="dk-sg-on" title="<?= h($org['name']) ?>"><?= h($org['name']) ?></span>
                            <?php if ($org['owner']): ?><span class="dk-sg-tag"><?= h(__('owner')) ?></span><?php endif; ?>
                            <?php if ($org['you']): ?><span class="dk-sg-tag is-you"><?= h(__('your org')) ?></span><?php endif; ?>
                            <?php if ($org['extend']): ?>
                                <i class="fas fa-user-plus dk-sg-ext" title="<?= h(__('Can add organisations')) ?>" aria-label="<?= h(__('Can add organisations')) ?>"></i>
                            <?php endif; ?>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
            <?php if ($peek['more']): ?>
                <a class="dk-sg-more" href="<?= h($groupUrl) ?>"><?= h(__('+%s more · open the group', $peek['more'])) ?></a>
            <?php endif; ?>
        <?php endif; ?>
    </section>

    <?php if ($peek['reach'] !== null): ?>
        <section class="dk-pop-sec">
            <h4><i class="fas fa-route"></i><?= h(__('Reach')) ?></h4>
            <p class="dk-sg-p"><?php if ($peek['reach']['mode'] !== null): ?><b><?= h($peek['reach']['mode']) ?>:</b> <?php endif; ?><?= h($peek['reach']['text']) ?></p>
        </section>
    <?php endif; ?>

    <?php foreach ($peek['notes'] as $note): ?>
        <section class="dk-pop-sec">
            <h4><i class="fas fa-align-left"></i><?= h($note['label']) ?></h4>
            <p class="dk-sg-p is-quiet"><?= h($note['text']) ?></p>
        </section>
    <?php endforeach; ?>

    <div class="dk-pop-foot dk-sg-foot">
        <a href="<?= h($baseurl . '/events/index/searchsharinggroup:' . (int)$peek['id']) ?>"><i class="fas fa-filter"></i><?= h(__('Only this group')) ?></a>
        <a href="<?= h($groupUrl) ?>"><i class="fas fa-arrow-up-right-from-square"></i><?= h(__('Open group')) ?></a>
    </div>
</div>
