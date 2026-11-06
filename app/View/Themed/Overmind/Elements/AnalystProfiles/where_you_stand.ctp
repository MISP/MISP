<?php
/**
 * The index's banner: which profile scores the reader and how MISP got
 * there, beside what this instance lets a profile do.
 *
 * The enrichment line asks misp-modules, so analyst-profile-cards.js
 * fills it in after the page and keeps its detail in the modal it opens.
 *
 * @var array|null $in_force
 * @var bool $scoring_off
 * @var array|null $default The row the instance setting names
 * @var array $scopes Scope => label, in resolution order
 * @var array $answers Scope => `profile` or `reason`
 * @var string|null $won_by
 * @var array $unresolved Declarations that resolved to nothing
 * @var array $capabilities
 * @var bool $may_select_for_instance
 * @var array $comparison_set
 * @var int $comparison_limit
 * @var array|null $shipped Site admins only
 */
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');

$hopReason = array(
    'missing' => __('the profile it named is gone'),
    'disabled' => __('the profile it named is switched off'),
    'unreadable' => __('it may not use the profile it named'),
);
$scopeWord = array(
    'user' => __('Your choice'),
    'org' => __('Your organisation\'s choice'),
    'instance' => __('The instance\'s choice'),
);
$reasonWord = array(
    'missing' => __('names a profile that is no longer on this instance'),
    'disabled' => __('names a profile that has been switched off'),
    'unreadable' => __('names a profile this scope may not use'),
);

// The pill each status tone takes, and the link to a setting for those who may change it.
$pill = array('ok' => 't-force', 'warn' => 't-over', 'plain' => 't-plain');
$settings = function (array $cap) use ($may_select_for_instance) {
    if (!$may_select_for_instance) {
        return '';
    }
    return '<a class="ap-st-act" href="' . h(Router::url(array(
            'controller' => 'servers', 'action' => 'serverSettings',
            $cap['tab'])) . '#setting=' . $cap['setting'])
        . '" title="' . h(sprintf(__('Change %s'), $cap['setting'])) . '">'
        . h(__('Settings')) . '</a>';
};

$hover = $capabilities['hover_card'];
$hoverTone = $hover['on'] ? 'ok' : 'plain';
$auto = $capabilities['enrichment_auto_run'];
$autoWord = array(
    'off' => __('Off'),
    'site_admin' => __('Site admins only'),
    'on' => __('On'),
);
// Allowed to run without a press, with no module switched on, runs nothing.
$autoTone = $auto['state'] === 'off'
    ? 'plain'
    : ($capabilities['enrichment_modules']['on'] ? 'ok' : 'warn');

if ($shipped !== null) {
    $loadable = array_filter($shipped['profiles'], function ($profile) {
        return $profile['state'] !== 'current';
    });
    $shippedTone = empty($loadable) ? 'ok' : 'warn';
    $shippedTitle = empty($shipped['retired']) ? '' : __n(
        '%s is no longer shipped by MISP. It stays, because a profile may have been forked from it.',
        '%s are no longer shipped by MISP. They stay, because a profile may have been forked from them.',
        count($shipped['retired']),
        implode(', ', array_column($shipped['retired'], 'name')));
}
?>
<section class="ap-stand" aria-label="<?= h(__('Where you stand')) ?>">
    <div class="ap-stand-main" data-tour="ap-resolution">
        <div class="ap-stand-head">
            <?php if ($scoring_off): ?>
                <h2 class="ap-stand-title is-off"><?= h(
                    __('Nothing scores your pages')) ?></h2>
                <p class="ap-stand-say"><?= h(__('No profile applies to you, so'
                    . ' nothing on this instance is scored. Value pages still'
                    . ' show their evidence; none of them shows a signal'
                    . ' strength.')) ?></p>
                <?php if ($default !== null && !$default['enabled']): ?>
                    <?= $this->Form->postLink(
                        sprintf(__('Enable %s'), $default['name']),
                        array('action' => 'enable', $default['id']),
                        array('class' => 'btn btn-sm btn-outline-primary mt-2')
                    ) ?>
                <?php endif; ?>
            <?php else: ?>
                <h2 class="ap-stand-title"><?= sprintf(
                    h(__('%s scores every value page you open')),
                    '<a href="' . h($this->Html->url(array('action' => 'view',
                        $in_force['id']))) . '">' . h($in_force['name']) . '</a>'
                ) ?></h2>
                <p class="ap-stand-say"><?= h(__('It stays in force until you'
                    . ' choose or enable another.')) ?></p>
            <?php endif; ?>
        </div>

        <ol class="ap-chain" aria-label="<?= h(__('Resolution order')) ?>">
            <?php $step = 1; ?>
            <?php foreach ($scopes as $scope => $label): ?>
                <?php
                $answer = $answers[$scope];
                $won = $won_by === $scope;
                ?>
                <li class="ap-hop<?= $won ? ' is-win' : ''
                    ?><?= $answer['reason'] !== null ? ' is-warn' : '' ?>">
                    <span class="ap-hop-n"><?= h($step++) ?></span>
                    <span class="ap-hop-t">
                        <span class="ap-hop-l"><?= h($label) ?></span>
                        <?php if ($answer['profile'] !== null): ?>
                            <a class="ap-hop-a" href="<?= h($this->Html->url(
                                array('action' => 'view',
                                    $answer['profile']['id']))) ?>"><?= h(
                                $answer['profile']['name']) ?></a>
                        <?php elseif ($answer['reason'] !== null): ?>
                            <span class="ap-hop-a"><?= h(
                                isset($hopReason[$answer['reason']])
                                    ? $hopReason[$answer['reason']]
                                    : $answer['reason']) ?></span>
                        <?php else: ?>
                            <span class="ap-hop-a is-none"><?= h(
                                __('no answer')) ?></span>
                        <?php endif; ?>
                    </span>
                    <?php if ($won): ?>
                        <span class="pill t-force"><i class="fas fa-check"
                            aria-hidden="true"></i> <?= h(__('answers')) ?></span>
                    <?php endif; ?>
                </li>
            <?php endforeach; ?>
        </ol>

        <?php foreach ($unresolved as $scope => $problem): ?>
            <p class="ap-stand-warn">
                <i class="fas fa-triangle-exclamation" aria-hidden="true"></i>
                <?= h(sprintf(
                    __('%1$s %2$s (%3$s). The next scope is answering'
                        . ' instead.'),
                    isset($scopeWord[$scope]) ? $scopeWord[$scope] : $scope,
                    isset($reasonWord[$problem['reason']])
                        ? $reasonWord[$problem['reason']]
                        : $problem['reason'],
                    isset($problem['name'])
                        ? $problem['name']
                        : substr($problem['uuid'], 0, 8)
                )) ?>
            </p>
        <?php endforeach; ?>

        <p class="ap-stand-note"><?= h(__('MISP asks these three in order and'
            . ' takes the first answer. Choosing a profile MISP ships keeps it'
            . ' up to date as MISP corrects it; forking freezes a copy you own'
            . ' and can edit.')) ?></p>
    </div>

    <div class="ap-stand-side" data-tour="ap-standing">
        <div class="ap-stand-k"><?= h(__('Status')) ?></div>
        <dl class="ap-st">
            <div class="ap-st-i" data-ap-enrichment data-tone="busy" title="<?= h(__(
                'The enrichment modules the profiles ask for, and how many of'
                . ' them can run here.')) ?>">
                <dt><i class="fas fa-puzzle-piece" aria-hidden="true"></i><?= h(
                    __('Enrichment modules')) ?></dt>
                <dd><span class="pill t-plain" data-ap-summary><span
                    class="spinner-border spinner-border-sm" aria-hidden="true"></span>
                    <?= h(__('checking')) ?></span></dd>
                <dd><button type="button" class="ap-st-act" data-bs-toggle="modal"
                            data-bs-target="#ap-enrichment-modal" data-ap-open
                            hidden></button></dd>
            </div>

            <div class="ap-st-i" data-tone="<?= h($autoTone) ?>" title="<?= h(
                $autoTone === 'warn'
                    ? __('Allowed, but no enrichment module is switched on here,'
                        . ' so nothing runs.')
                    : __('Whether the modules a profile marks to run on their own'
                        . ' do so when a value page opens, without anybody'
                        . ' pressing Enrich.')) ?>">
                <dt><i class="fas fa-bolt" aria-hidden="true"></i><?= h(
                    __('Enrichment without a press')) ?></dt>
                <dd><span class="pill <?= $pill[$autoTone] ?>"><?= h(
                    isset($autoWord[$auto['state']])
                        ? $autoWord[$auto['state']]
                        : $auto['state']) ?></span></dd>
                <dd><?= $settings($auto) ?></dd>
            </div>

            <div class="ap-st-i" data-tone="<?= h($hoverTone) ?>" title="<?= h(__(
                'The card a value opens when you hover it, with its'
                . ' assessment.')) ?>">
                <dt><i class="fas fa-hand-pointer" aria-hidden="true"></i><?= h(
                    __('Hover card')) ?></dt>
                <dd><span class="pill <?= $pill[$hoverTone] ?>"><?= h(
                    $hover['on'] ? __('On') : __('Off')) ?></span></dd>
                <dd><?= $settings($hover) ?></dd>
            </div>

            <?php if ($shipped !== null): ?>
                <div class="ap-st-i" data-tone="<?= h($shippedTone) ?>"<?=
                    $shippedTitle === '' ? '' : ' title="' . h($shippedTitle) . '"' ?>>
                    <dt><i class="fas fa-box-open" aria-hidden="true"></i><?= h(
                        __('Shipped profiles')) ?></dt>
                    <dd><span class="pill <?= $pill[$shippedTone] ?>"><?= h(
                        empty($loadable)
                            ? __('%s, all current', count($shipped['profiles']))
                            : __n('%s to load', '%s to load', count($loadable),
                                count($loadable))) ?></span></dd>
                    <dd>
                        <?php if (!empty($loadable)): ?>
                            <?php $loadUrl = $this->Html->url(array('action' => 'update')); ?>
                            <a class="ap-st-act" href="<?= h($loadUrl) ?>"
                               onclick="<?= h('event.preventDefault(); openModal('
                                   . json_encode($loadUrl) . ", 'md');") ?>"><?= h(
                                __('Load')) ?></a>
                        <?php endif; ?>
                    </dd>
                </div>
            <?php endif; ?>

            <div class="ap-st-i" data-tone="plain" title="<?= h(
                empty($comparison_set)
                    ? __('Pin a value while editing a profile and it follows'
                        . ' you between profiles, so every change is judged on'
                        . ' the same value.')
                    : __('These follow you into every profile you open, so a'
                        . ' change is judged on the same values each time.')) ?>">
                <dt><i class="fas fa-thumbtack" aria-hidden="true"></i><?= h(
                    __('Pinned values')) ?></dt>
                <dd><span class="pill t-plain"><?= h(sprintf(__('%1$s of %2$s'),
                    count($comparison_set), $comparison_limit)) ?></span></dd>
                <dd>
                    <?php if (!empty($comparison_set)): ?>
                        <div class="dropdown">
                            <button type="button" class="ap-st-act"
                                    data-bs-toggle="dropdown" aria-expanded="false"><?= h(
                                __('Show')) ?></button>
                            <ul class="dropdown-menu dropdown-menu-end ap-pins">
                                <?php foreach ($comparison_set as $value): ?>
                                    <li class="ap-pin">
                                        <span class="ap-pin-v" title="<?= h($value) ?>"><?= h(
                                            $value) ?></span>
                                        <?= $this->Form->postLink(
                                            __('unpin'),
                                            array('action' => 'unpin',
                                                ValueUrlTool::encode($value)),
                                            array('class' => 'ap-pin-x')
                                        ) ?>
                                    </li>
                                <?php endforeach; ?>
                            </ul>
                        </div>
                    <?php endif; ?>
                </dd>
            </div>
        </dl>
    </div>
</section>
