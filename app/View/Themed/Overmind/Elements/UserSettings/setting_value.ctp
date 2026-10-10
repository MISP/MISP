<?php
/**
 * A user setting's value as a click-to-copy chip.
 *
 * @var mixed $value Decoded value (UserSetting::afterFind json_decodes it)
 */
$value = $value ?? null;
$flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
$isList = is_array($value) && array_is_list($value);

if ($value === null || $value === '' || $value === []) {
    $kind = 'empty';
    $kindLabel = __('Empty');
    $preview = '';
    $copy = '';
} elseif (is_bool($value)) {
    $kind = 'bool';
    $kindLabel = __('Boolean');
    $preview = $value ? 'true' : 'false';
    $copy = $preview;
} elseif (is_int($value) || is_float($value)) {
    $kind = 'number';
    $kindLabel = __('Number');
    $preview = (string)$value;
    $copy = $preview;
} elseif (is_string($value)) {
    $kind = 'text';
    $kindLabel = __('Text');
    $preview = $value;
    $copy = $value;
} else {
    $kind = $isList ? 'list' : 'object';
    $kindLabel = $isList
        ? __n('%s item', '%s items', count($value), count($value))
        : __n('%s key', '%s keys', count($value), count($value));
    $preview = json_encode($value, $flags);
    $copy = json_encode($value, $flags | JSON_PRETTY_PRINT);
}
$expandable = in_array($kind, ['list', 'object'], true) && mb_strlen($preview) > 48;
$prettyId = 'ov-sv-' . uniqid();
$chipClass = 'btn btn-sm d-inline-flex align-items-center gap-2 mw-100 text-start'
    . ' border rounded-2 bg-body-tertiary text-body py-1 ps-1 pe-2';
$kindClass = 'badge d-inline-flex align-items-center gap-1 flex-shrink-0'
    . ' bg-body border text-body-secondary text-uppercase fw-semibold';
?>
<div class="ov-setting-value d-flex flex-wrap align-items-center gap-1">
    <?php if ($kind === 'empty'): ?>
        <span class="<?= $chipClass ?> pe-1 pe-none">
            <span class="<?= $kindClass ?>"><?= h($kindLabel) ?></span>
        </span>
    <?php else: ?>
        <button type="button" class="<?= $chipClass ?> ov-copy-target focus-ring"
                title="<?= h(__('Click to copy')) ?>"
                data-copy-value="<?= h($copy) ?>"
                data-copy-msg="<?= h(__('Value copied to clipboard')) ?>"
                onclick="copyValueToClipboard(this.dataset.copyValue, this.dataset.copyMsg)">
            <span class="<?= $kindClass ?>">
                <?php if ($kind === 'object'): ?><span class="font-monospace text-primary">{ }</span>
                <?php elseif ($kind === 'list'): ?><span class="font-monospace text-primary">[ ]</span>
                <?php elseif ($kind === 'bool'): ?><i class="fas fa-circle fa-2xs <?= $value ? 'text-success' : 'text-body-secondary' ?>"></i>
                <?php endif; ?>
                <?= h($kindLabel) ?>
            </span>
            <code class="text-truncate text-body small"><?= h($preview) ?></code>
            <i class="far fa-copy text-body-secondary small flex-shrink-0" aria-hidden="true"></i>
        </button>
        <?php if ($expandable): ?>
            <button type="button" class="btn btn-sm btn-link link-secondary p-1 lh-1"
                    title="<?= h(__('Show the full value')) ?>"
                    aria-expanded="false" aria-controls="<?= h($prettyId) ?>"
                    onclick="var open = document.getElementById(this.getAttribute('aria-controls')).classList.toggle('d-none') === false;
                             this.setAttribute('aria-expanded', open ? 'true' : 'false');
                             this.firstElementChild.classList.toggle('fa-chevron-up', open);
                             this.firstElementChild.classList.toggle('fa-chevron-down', !open);">
                <i class="fas fa-chevron-down small" aria-hidden="true"></i>
            </button>
            <pre id="<?= h($prettyId) ?>" class="d-none w-100 mb-0 p-2 overflow-auto border rounded-2 bg-body-tertiary small text-body"><?= h($copy) ?></pre>
        <?php endif; ?>
    <?php endif; ?>
</div>
