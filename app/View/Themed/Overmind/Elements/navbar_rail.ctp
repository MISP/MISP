<?php
/**
 * The rail navbar: the same NavbarHelper::build() menus as navbar.ctp, each
 * group opening as a mega-panel. Behaviour is js/overmind-rail.js; the look
 * is scss/_misp-rail.scss in the theme.
 *
 * @var array $menus
 * @var string $baseurl
 */
$slots = [];
$end = [];
foreach ($menus['right'] as $item) {
    if (($item['type'] ?? null) === 'intelGraph') {
        $slots[] = $item;
    } else {
        $end[] = $item;
    }
}
?>
<nav class="rail-nav" aria-label="<?= __('Main') ?>">
    <div class="rail-bar">
        <a class="rail-brand" href="<?= empty($homepage['path']) ? $baseurl . '/' : $baseurl . h($homepage['path']) ?>"<?= empty($mispVersionFull) ? '' : ' title="' . h(__('MISP %s', $mispVersionFull)) . '"' ?>>
            <?= $this->Html->image('misp-logo-main-cmyk-icon coul.png', ['alt' => __('MISP Logo')]) ?>
        </a>
        <div class="rail-menu" id="rail-menu">
            <ul class="rail-groups rail-groups--start">
                <?php foreach ($menus['left'] as $item): ?>
                    <?= $this->element('navbar_rail_group', ['item' => $item]) ?>
                <?php endforeach; ?>
            </ul>
            <?php foreach ($slots as $item): ?>
                <?= $this->element('navbar_rail_slot', ['item' => $item]) ?>
            <?php endforeach; ?>
            <ul class="rail-groups rail-groups--end">
                <?php foreach ($end as $item): ?>
                    <?= $this->element('navbar_rail_group', ['item' => $item, 'alignEnd' => true]) ?>
                <?php endforeach; ?>
            </ul>
        </div>
        <button type="button" class="rail-toggle" aria-label="<?= __('Menu') ?>" aria-controls="rail-menu" aria-expanded="false">
            <i class="fas fa-bars" aria-hidden="true"></i>
        </button>
    </div>
</nav>
<?= $this->element('navbar_actions') ?>
