<?php
/**
 * The facts about a profile, each with its label: who owns it, the
 * version MISP shipped (only on a profile MISP ships: a fork is born at
 * version 1 and stays there), and how many of its signals are on.
 *
 * @var array $profile
 * @var array|null $standing This profile's row of the index board
 */
if ($standing === null) {
    return;
}
?>
<section class="card ap-rcard" aria-label="<?= h(__('About this profile')) ?>">
    <header class="ap-rcard-h">
        <span class="ap-vcard-ico" aria-hidden="true"><i class="fas fa-circle-info"></i></span>
        <h2 class="ap-rcard-t"><?= h(__('About this profile')) ?></h2>
    </header>
    <dl class="ap-about">
        <div>
            <dt><?= h(__('Owner')) ?></dt>
            <dd><?= h($standing['owner']) ?></dd>
        </div>
        <?php if (!empty($profile['default'])): ?>
            <div>
                <dt><?= h(__('Shipped version')) ?></dt>
                <dd>
                    v<?= h($profile['version']) ?>
                    <?php if ($profile['edited_here']): ?>
                        <span class="ap-about-sub" title="<?= h(__('Changed on'
                            . ' this instance since MISP last wrote it. The next'
                            . ' shipped update replaces the change.')) ?>">
                            · <?= h(__('edited here')) ?></span>
                    <?php endif; ?>
                </dd>
            </div>
        <?php endif; ?>
        <div>
            <dt><?= h(__('Signals on')) ?></dt>
            <dd><?= h(sprintf(__('%s of %s'), $standing['signals']['enabled'],
                $standing['signals']['configured'])) ?></dd>
        </div>
    </dl>
</section>
