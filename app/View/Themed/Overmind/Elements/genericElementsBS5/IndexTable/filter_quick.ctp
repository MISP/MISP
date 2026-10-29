<?php
/**
 * A `button` child of a picker bar, drawn in its Filters panel: a switch
 * when the child says whether it is `pressed`, a shortcut link otherwise.
 * The url is where clicking leads, on or off; `count` sits beside the label.
 *
 * @var array $child
 */
$isSwitch = array_key_exists('pressed', $child);
$on = !empty($child['pressed']);
$url = (string)($child['url'] ?? '#');
$nav = empty($child['onclick']) && !preg_match('/^(#|javascript:)/i', $url);
$key = $child['id'] ?? 'toggle-' . substr(md5((string)($child['label'] ?? '')), 0, 8);
$classes = 'ifp-quick' . ($isSwitch ? '' : ' is-link') . ($on ? ' is-on' : '');
?>
<a href="<?= h($url) ?>" class="<?= $classes ?>" data-ifp-swap="<?= h($key) ?>"<?php
   if ($isSwitch): ?> role="switch" aria-checked="<?= $on ? 'true' : 'false' ?>"<?php endif; ?><?php
   if (!empty($child['id'])): ?> id="<?= h($child['id']) ?>"<?php endif; ?><?php
   if ($nav): ?> data-ifp-nav<?php endif; ?><?php
   if (!empty($child['title'])): ?> title="<?= h($child['title']) ?>"<?php endif; ?><?php
   if (!empty($child['onclick'])): ?> onclick="<?= h($child['onclick']) ?>"<?php endif; ?>>
    <?php if ($isSwitch): ?>
        <span class="ifp-switch" aria-hidden="true"></span>
    <?php endif; ?>
    <?php if (!empty($child['icon'])): ?>
        <i class="<?= h($child['icon']) ?>" aria-hidden="true"></i>
    <?php endif; ?>
    <span class="ifp-quick-label"><?= h($child['label']) ?></span>
    <?php if (!empty($child['count'])): ?>
        <span class="ifp-quick-n"><?= h(number_format((int)$child['count'])) ?></span>
    <?php endif; ?>
    <?php if (!$isSwitch): ?>
        <i class="fas fa-arrow-right ifp-quick-go" aria-hidden="true"></i>
    <?php endif; ?>
</a>
