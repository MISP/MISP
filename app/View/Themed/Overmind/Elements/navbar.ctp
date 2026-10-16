<nav class="rc-nav<?= empty($builtinPalette) ? '' : ' rc-daylight' ?>" aria-label="<?= __('Main') ?>">
    <div class="rc-bar">
        <a class="rc-brand" href="<?= empty($homepage['path']) ? $baseurl .'/' : $baseurl . h($homepage['path']) ?>"<?= empty($mispVersionFull) ? '' : ' title="' . h(__('MISP %s', $mispVersionFull)) . '"' ?>>
            <?= $this->Html->image('misp-logo-main-cmyk-icon coul.png', ['alt' => __('MISP Logo')]) ?>
            <?php if (!empty($mispVersionFull)): ?>
                <span class="rc-version"><?= h($mispVersionFull) ?></span>
            <?php endif; ?>
        </a>

        <button type="button" class="rc-toggler" aria-expanded="false" aria-controls="rc-collapse" aria-label="<?= __('Menu') ?>">
            <i class="fas fa-bars rc-burger" aria-hidden="true"></i>
            <i class="fas fa-xmark rc-x" aria-hidden="true"></i>
        </button>

        <div class="rc-collapse" id="rc-collapse">
            <ul class="rc-groups rc-groups-left">
                <?php foreach ($menus['left'] as $item): ?>
                    <?= $this->element('navbar_nav', ['item' => $item]) ?>
                <?php endforeach; ?>
            </ul>

            <ul class="rc-groups rc-groups-right">
                <?php foreach ($menus['right'] as $item): ?>
                    <?= $this->element('navbar_nav', ['item' => $item, 'alignEnd' => true]) ?>
                <?php endforeach; ?>
            </ul>
        </div>
    </div>
    <div class="rc-scrim" aria-hidden="true"></div>
</nav>
<?= $this->element('navbar_actions') ?>
