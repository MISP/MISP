<?php
/**
 * One entry of a rail panel. A nested group lists its children under its
 * heading, always visible; the panel has no flyouts.
 *
 * @var array $item
 * @var string $subId id for a nested group's heading
 */
$type = $item['type'] ?? null;
?>
<?php if (!empty($item['divider'])): ?>
    <li class="rail-sep" role="separator"></li>
<?php elseif ($type === 'message'): ?>
    <li class="rail-msg" role="note">
        <span class="rail-msg-t"><?= h($item['label']) ?></span>
        <?php if (!empty($item['description'])): ?>
            <span class="rail-desc"><?= h($item['description']) ?></span>
        <?php endif; ?>
    </li>
<?php elseif ($type === 'theme'): ?>
    <li>
        <button type="button" class="rail-item rail-theme setTheme<?= $item['on'] ? ' is-on' : '' ?>" data-theme="<?= h($item['theme']) ?>" aria-pressed="<?= $item['on'] ? 'true' : 'false' ?>">
            <span class="rail-radio" aria-hidden="true"></span>
            <span class="rail-lbl">
                <?= h($item['label']) ?>
                <?php if (!empty($item['description'])): ?>
                    <span class="rail-desc"><?= h($item['description']) ?></span>
                <?php endif; ?>
            </span>
        </button>
    </li>
<?php elseif ($type === 'bootstrapTheme' && !empty($item['secret'])): ?>
    <li class="theme-secret" hidden>
        <button type="button" class="rail-item rail-bstheme set-bootstrap-theme is-secret" data-theme="<?= h($item['theme']) ?>">
            <span class="rail-radio" aria-hidden="true"></span>
            <span class="rail-lbl"><span class="secret-mask">???</span><span class="secret-name"><?= h($item['label']) ?></span></span>
            <span class="rail-mode" title="<?= h($item['modeLabel']) ?>"><i class="<?= h($item['modeIcon']) ?> fa-fw" aria-hidden="true"></i><span class="visually-hidden"><?= h($item['modeLabel']) ?></span></span>
        </button>
    </li>
<?php elseif ($type === 'bootstrapTheme'): ?>
    <li>
        <button type="button" class="rail-item rail-bstheme set-bootstrap-theme<?= $item['on'] ? ' is-on' : '' ?>" data-theme="<?= h($item['theme']) ?>" title="<?= h($item['description']) ?>"<?= $item['on'] ? ' aria-current="true"' : '' ?>>
            <span class="rail-radio" aria-hidden="true"></span>
            <span class="rail-lbl"><?= h($item['label']) ?></span>
            <span class="rail-mode" title="<?= h($item['modeLabel']) ?>"><i class="<?= h($item['modeIcon']) ?> fa-fw" aria-hidden="true"></i><span class="visually-hidden"><?= h($item['modeLabel']) ?></span></span>
        </button>
    </li>
<?php elseif ($type === 'darkMode'): ?>
    <?php // updateDarkModeUI() in mispOvermind.js keeps aria-checked and the icon current. ?>
    <li>
        <button type="button" class="rail-item toggle-dark-mode" role="switch" aria-checked="false">
            <?= $this->element('navbar_rail_glyph', ['item' => $item, 'extraClass' => 'dark-mode-icon']) ?>
            <span class="rail-lbl"><?= h($item['label']) ?></span>
            <span class="rail-switch" aria-hidden="true"></span>
        </button>
    </li>
<?php elseif ($type === 'tutorial' || $type === 'setHomepage'): ?>
    <li>
        <button type="button" class="rail-item <?= $type === 'tutorial' ? 'onboarding-launch' : 'set-homepage' ?>">
            <?= $this->element('navbar_rail_glyph', ['item' => $item]) ?>
            <span class="rail-lbl"><?= h($item['label']) ?></span>
        </button>
    </li>
<?php elseif (!empty($item['children'])): ?>
    <li class="rail-sub">
        <span class="rail-subhead" id="<?= h($subId) ?>">
            <?= $this->element('navbar_rail_glyph', ['item' => $item]) ?>
            <span><?= h($item['label']) ?></span>
            <?php if (!empty($item['value'])): ?>
                <span class="rail-value"><?= h($item['value']) ?></span>
            <?php endif; ?>
        </span>
        <ul class="rail-sublist" aria-labelledby="<?= h($subId) ?>">
            <?php foreach ($item['children'] as $j => $child): ?>
                <?= $this->element('navbar_rail_item', ['item' => $child, 'subId' => $subId . '-' . $j]) ?>
            <?php endforeach; ?>
        </ul>
    </li>
<?php else: ?>
    <li>
        <a class="rail-item" href="<?= h($item['url']) ?>">
            <?= $this->element('navbar_rail_glyph', ['item' => $item]) ?>
            <span class="rail-lbl"><?= h($item['label']) ?></span>
        </a>
    </li>
<?php endif; ?>
