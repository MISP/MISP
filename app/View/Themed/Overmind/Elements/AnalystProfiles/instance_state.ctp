<?php
/**
 * What this instance lets a profile do, in four lines.
 *
 * Three of the four are settings a profile cannot see and cannot
 * override, and each of them produces the same symptom when off: a
 * profile that plainly says it does something, and a page where it
 * does not happen. The reader who hits that has nowhere to look — the
 * profile is not lying, the instance is answering. So the index says
 * what the instance answers, once, next to the profiles it governs.
 *
 * Shown to everybody: these are instance settings, not records, and a
 * reader who cannot change one still needs to know it is the reason
 * hovering a value does nothing. Only a site admin gets the link.
 *
 * @var array $capabilities From AnalystProfilesController::__capabilities()
 * @var bool $may_select_for_instance Stands in for site admin here
 */
$autoWord = array(
    'off' => __('off'),
    'site_admin' => __('site admins only'),
    'on' => __('on'),
);
/*
 * Two or three words, because this is a value in a key/value list and
 * the key already said *instance profile*. The sentence saying which
 * profile and what happens next is the warning above the table; this
 * is the same fact where a reader is looking at the other three.
 */
$reasonWord = array(
    'missing' => __('not here'),
    'disabled' => __('switched off'),
    'unreadable' => __('not permitted'),
);

$auto = $capabilities['enrichment_auto_run'];
$modules = $capabilities['enrichment_modules'];
$hover = $capabilities['hover_card'];
$instance = $capabilities['instance_profile'];

/*
 * Render one line. `$tone` is ok | off | warn, and warn is reserved
 * for a setting that is on and doing nothing anyway — the only one of
 * these states somebody has to act on rather than merely know.
 */
$line = function ($label, $value, $tone, $cap) use ($may_select_for_instance) {
    $out = '<div class="ap-cap ap-cap-' . h($tone) . '">';
    $out .= '<span class="ap-cap-k" title="' . h($cap['setting']) . '">'
        . h($label) . '</span>';
    $out .= '<span class="ap-cap-v">';
    if ($may_select_for_instance) {
        $out .= '<a href="' . h(Router::url(array(
            'controller' => 'servers', 'action' => 'serverSettings',
            $cap['tab']))) . '" title="' . h(sprintf(
                __('Change %s'), $cap['setting'])) . '">' . h($value) . '</a>';
    } else {
        $out .= h($value);
    }
    $out .= '</span></div>';
    return $out;
};
?>
<div class="bench-sec">
    <span><?= h(__('This instance')) ?></span>
</div>
<div class="ap-caps">
    <?= $line(__('Hover card'), $hover['on'] ? __('on') : __('off'),
        $hover['on'] ? 'ok' : 'off', $hover) ?>
    <?= $line(__('Enrichment modules'), $modules['on'] ? __('on') : __('off'),
        $modules['on'] ? 'ok' : 'off', $modules) ?>
    <?= $line(
        __('Enrichment without a press'),
        isset($autoWord[$auto['state']])
            ? $autoWord[$auto['state']]
            : $auto['state'],
        $auto['state'] === 'off'
            ? 'off'
            : ($modules['on'] ? 'ok' : 'warn'),
        $auto
    ) ?>
    <div class="ap-cap <?= $instance['reason'] === null ? '' : 'ap-cap-warn' ?>">
        <span class="ap-cap-k" title="<?= h($instance['setting']) ?>">
            <?= h(__('Instance profile')) ?></span>
        <span class="ap-cap-v">
            <?php if ($instance['reason'] !== null): ?>
                <?= h(isset($reasonWord[$instance['reason']])
                    ? $reasonWord[$instance['reason']]
                    : $instance['reason']) ?>
            <?php elseif ($instance['id'] !== null): ?>
                <a href="<?= h($this->Html->url(array(
                    'action' => 'view', $instance['id']))) ?>"><?= h(
                    $instance['name']) ?></a>
            <?php else: ?>
                <?= h(__('none named')) ?>
            <?php endif; ?>
        </span>
    </div>
</div>
<?php if ($auto['state'] !== 'off' && !$modules['on']): ?>
    <p class="wb-sub mt-1 mb-0">
        <?= h(__('A profile may run enrichment here, but this instance has'
            . ' no modules switched on, so nothing runs.')) ?>
    </p>
<?php endif; ?>
