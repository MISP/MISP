<?php
/**
 * One entry of a navbar dropdown. A nested group renders its children as a
 * flyout through this same element.
 *
 * @var array $item
 * @var string $subId id for the flyout of a nested group
 */
$type = $item['type'] ?? null;
?>
<?php if (!empty($item['divider'])): ?>
    <li class="rc-divider" role="separator"></li>
<?php elseif ($type === 'message'): ?>
    <li class="rc-note">
        <span class="rc-note-label"><?= h($item['label']) ?></span>
        <?php if (!empty($item['description'])): ?>
            <span class="rc-desc"><?= h($item['description']) ?></span>
        <?php endif; ?>
    </li>
<?php elseif ($type === 'theme'): ?>
    <li>
        <button type="button" class="rc-item rc-theme setTheme<?= $item['on'] ? ' is-on' : '' ?>" data-theme="<?= h($item['theme']) ?>" aria-pressed="<?= $item['on'] ? 'true' : 'false' ?>">
            <span class="rc-ico" aria-hidden="true"><i class="fas fa-desktop fa-fw"></i></span>
            <span class="rc-text">
                <span class="rc-theme-head">
                    <span class="rc-theme-name"><?= h($item['label']) ?></span>
                    <span class="rc-badge <?= $item['on'] ? 'rc-badge-on' : 'rc-badge-off' ?>"><?= $item['on'] ? __('ON') : __('OFF') ?></span>
                </span>
                <?php if (!empty($item['description'])): ?>
                    <span class="rc-desc"><?= h($item['description']) ?></span>
                <?php endif; ?>
            </span>
        </button>
    </li>
<?php elseif ($type === 'bootstrapTheme' && !empty($item['secret'])): ?>
    <li class="theme-secret" hidden>
        <button type="button" class="rc-item rc-bstheme set-bootstrap-theme is-secret" data-theme="<?= h($item['theme']) ?>">
            <span class="rc-ico" aria-hidden="true"><i class="fas fa-check fa-fw"></i></span>
            <span class="rc-text"><span class="secret-mask">???</span><span class="secret-name"><?= h($item['label']) ?></span></span>
            <span class="rc-mode" title="<?= h($item['modeLabel']) ?>"><i class="<?= h($item['modeIcon']) ?> fa-fw" aria-hidden="true"></i><span class="visually-hidden"><?= h($item['modeLabel']) ?></span></span>
        </button>
    </li>
<?php elseif ($type === 'bootstrapTheme'): ?>
    <li>
        <button type="button" class="rc-item rc-bstheme set-bootstrap-theme<?= $item['on'] ? ' is-on' : '' ?>" data-theme="<?= h($item['theme']) ?>" title="<?= h($item['description']) ?>"<?= $item['on'] ? ' aria-current="true"' : '' ?>>
            <span class="rc-ico" aria-hidden="true"><i class="fas fa-check fa-fw"></i></span>
            <span class="rc-text"><?= h($item['label']) ?></span>
            <span class="rc-mode" title="<?= h($item['modeLabel']) ?>"><i class="<?= h($item['modeIcon']) ?> fa-fw" aria-hidden="true"></i><span class="visually-hidden"><?= h($item['modeLabel']) ?></span></span>
        </button>
    </li>
<?php elseif ($type === 'darkMode'): ?>
    <?php // updateDarkModeUI() in mispOvermind.js keeps aria-checked and the icon current. ?>
    <li>
        <button type="button" class="rc-item toggle-dark-mode" role="switch" aria-checked="false">
            <?= $this->element('navbar_glyph', ['item' => $item, 'extraClass' => 'dark-mode-icon']) ?>
            <span class="rc-text"><?= h($item['label']) ?></span>
            <span class="rc-switch" aria-hidden="true"></span>
        </button>
    </li>
<?php elseif ($type === 'tutorial' || $type === 'setHomepage'): ?>
    <li>
        <button type="button" class="rc-item <?= $type === 'tutorial' ? 'onboarding-launch' : 'set-homepage' ?>">
            <?= $this->element('navbar_glyph', ['item' => $item]) ?>
            <span class="rc-text"><?= h($item['label']) ?></span>
        </button>
    </li>
<?php elseif (!empty($item['children'])): ?>
    <?php
        $wide = false;
        foreach ($item['children'] as $child) {
            if (in_array($child['type'] ?? null, ['theme', 'message'], true)) {
                $wide = true;
            }
        }
    ?>
    <li class="rc-sub">
        <button type="button" class="rc-item rc-subtrigger" aria-expanded="false" aria-controls="<?= $subId ?>">
            <?= $this->element('navbar_glyph', ['item' => $item]) ?>
            <span class="rc-text"><?= h($item['label']) ?></span>
            <?php if (!empty($item['value'])): ?>
                <span class="rc-value"><?= h($item['value']) ?></span>
            <?php endif; ?>
            <i class="rc-chev-r fas fa-chevron-right" aria-hidden="true"></i>
        </button>
        <ul class="rc-panel rc-flyout<?= $wide ? ' rc-wide' : '' ?>" id="<?= $subId ?>">
            <?php foreach ($item['children'] as $j => $child): ?>
                <?= $this->element('navbar_item', ['item' => $child, 'subId' => $subId . '-' . $j]) ?>
            <?php endforeach; ?>
        </ul>
    </li>
<?php else: ?>
    <li>
        <a class="rc-item" href="<?= h($item['url']) ?>">
            <?= $this->element('navbar_glyph', ['item' => $item]) ?>
            <span class="rc-text"><?= h($item['label']) ?></span>
        </a>
    </li>
<?php endif; ?>
