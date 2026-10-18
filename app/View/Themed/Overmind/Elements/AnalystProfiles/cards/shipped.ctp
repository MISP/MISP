<?php
/**
 * Whether the profiles MISP ships are current here, and what loading them
 * again would change. Site admins only.
 *
 * @var array $shipped From AnalystProfile::shippedStatus()
 */
$profiles = $shipped['profiles'];
$loadable = array_filter($profiles, function ($profile) {
    return $profile['state'] !== 'current';
});
$overwrites = array_filter($loadable, function ($profile) {
    return $profile['edited_here'];
});
$listed = array_filter($profiles, function ($profile) {
    return $profile['state'] !== 'current' || $profile['edited_here'];
});
$status = empty($loadable)
    ? array('text' => __('current'), 'tone' => 't-plain')
    : array('text' => __n('%s to load', '%s to load', count($loadable),
        count($loadable)), 'tone' => 't-over');
?>
<section class="ap-card ap-card-shipped" data-ap-card="shipped">
    <?= $this->element('AnalystProfiles/cards/head', array(
        'icon' => 'box-open',
        'title' => __('Shipped profiles'),
        'status' => $status,
    )) ?>
    <div class="ap-card-fig">
        <span class="ap-card-n"><?= h(count($profiles)) ?></span>
        <span class="ap-card-of"><?= h(empty($loadable)
            ? __('shipped by MISP, all matching its files')
            : __('shipped by MISP')) ?></span>
    </div>
    <?php if (!empty($listed)): ?>
        <ul class="ap-items">
            <?php foreach ($listed as $profile): ?>
                <li class="ap-item">
                    <span class="ap-item-main">
                        <?php if ($profile['id'] !== null): ?>
                            <a class="ap-item-label" href="<?= h($this->Html->url(array(
                                'action' => 'view', $profile['id']))) ?>"><?= h(
                                $profile['name']) ?></a>
                        <?php else: ?>
                            <span class="ap-item-label"><?= h($profile['name']) ?></span>
                        <?php endif; ?>
                        <span class="ap-item-meta">
                            <?php if ($profile['state'] === 'missing'): ?>
                                <?= h(__('not loaded yet')) ?>
                            <?php elseif ($profile['state'] === 'pending'): ?>
                                <?= h(sprintf('v%s → v%s', $profile['version'],
                                    $profile['file_version'])) ?>
                                <?= $profile['edited_here']
                                    ? '&middot; ' . h(__('edited here, loading replaces the edit'))
                                    : '' ?>
                            <?php else: ?>
                                <?= h(__('edited here; the next shipped update replaces the edit')) ?>
                            <?php endif; ?>
                        </span>
                    </span>
                </li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>
    <?php if (!empty($shipped['retired'])): ?>
        <p class="ap-card-line"><?= h(__n(
            '%s is no longer shipped by MISP. It stays, because a profile may have been forked from it.',
            '%s are no longer shipped by MISP. They stay, because a profile may have been forked from them.',
            count($shipped['retired']),
            implode(', ', array_column($shipped['retired'], 'name')))) ?></p>
    <?php endif; ?>
    <?php if (!empty($loadable)): ?>
        <footer class="ap-card-foot">
            <?= $this->Form->postLink(
                __n('Load %s profile', 'Load %s profiles', count($loadable), count($loadable)),
                array('action' => 'update'),
                array('class' => 'btn btn-sm btn-primary ap-fix'),
                empty($overwrites)
                    ? __('Load the profiles MISP ships? Forks are never touched.')
                    : __n('Load the profiles MISP ships? %s was edited here and the edit is replaced. Forks are never touched.',
                        'Load the profiles MISP ships? %s were edited here and the edits are replaced. Forks are never touched.',
                        count($overwrites),
                        implode(', ', array_column($overwrites, 'name')))
            ) ?>
        </footer>
    <?php endif; ?>
</section>
