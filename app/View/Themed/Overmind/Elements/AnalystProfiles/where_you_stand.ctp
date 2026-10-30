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
App::uses('ServerSettingGroups', 'Tools');

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

$hover = $capabilities['hover_card'];
$tone = array(
    'ok' => 'circle-check',
    'warn' => 'triangle-exclamation',
    'plain' => 'circle-info',
);

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
        <ul class="ap-health">
            <li class="ap-health-i" data-ap-enrichment data-tone="busy">
                <span class="ap-health-ico" aria-hidden="true"><span
                    class="spinner-border spinner-border-sm"></span></span>
                <span class="ap-health-t"><b><?= h(__('Enrichment')) ?></b>:
                    <span data-ap-summary><?= h(__('asking the modules'
                        . ' service…')) ?></span></span>
                <button type="button" class="btn btn-link btn-sm ap-health-act"
                        data-bs-toggle="modal" data-bs-target="#ap-enrichment-modal"
                        data-ap-open hidden></button>
            </li>

            <li class="ap-health-i" data-tone="<?= $hover['on'] ? 'ok' : 'plain' ?>">
                <span class="ap-health-ico" aria-hidden="true"><i class="fas fa-<?=
                    $tone[$hover['on'] ? 'ok' : 'plain'] ?>"></i></span>
                <span class="ap-health-t"><b><?= h(__('Hover card')) ?></b>:
                    <?= h($hover['on'] ? __('on') : __('off')) ?></span>
                <?php if ($may_select_for_instance): ?>
                    <a class="btn btn-link btn-sm ap-health-act" href="<?= h(
                        Router::url(array('controller' => 'servers',
                            'action' => 'serverSettings',
                            ServerSettingGroups::resolve($hover['tab'])))
                        . '#setting=' . $hover['setting']) ?>"
                       title="<?= h(sprintf(__('Change %s'),
                           $hover['setting'])) ?>"><?= h(__('Settings')) ?></a>
                <?php endif; ?>
            </li>

            <?php if ($shipped !== null): ?>
                <li class="ap-health-i" data-tone="<?= h($shippedTone) ?>"<?=
                    $shippedTitle === '' ? '' : ' title="' . h($shippedTitle) . '"' ?>>
                    <span class="ap-health-ico" aria-hidden="true"><i class="fas fa-<?=
                        $tone[$shippedTone] ?>"></i></span>
                    <span class="ap-health-t"><b><?= h(__('Shipped profiles')) ?></b>:
                        <?= h(empty($loadable)
                            ? __('%s, all current', count($shipped['profiles']))
                            : __n('%s to load', '%s to load', count($loadable),
                                count($loadable))) ?></span>
                    <?php if (!empty($loadable)): ?>
                        <?php $loadUrl = $this->Html->url(array('action' => 'update')); ?>
                        <a class="btn btn-sm btn-primary ap-health-btn"
                           href="<?= h($loadUrl) ?>"
                           onclick="<?= h('event.preventDefault(); openModal('
                               . json_encode($loadUrl) . ", 'md');") ?>"><?= h(
                            __('Load')) ?></a>
                    <?php endif; ?>
                </li>
            <?php endif; ?>

            <li class="ap-health-i" data-tone="plain" title="<?= h(
                empty($comparison_set)
                    ? __('Pin a value while editing a profile and it follows'
                        . ' you between profiles, so every change is judged on'
                        . ' the same value.')
                    : __('These follow you into every profile you open, so a'
                        . ' change is judged on the same values each time.')) ?>">
                <span class="ap-health-ico" aria-hidden="true"><i
                    class="fas fa-thumbtack"></i></span>
                <span class="ap-health-t"><b><?= h(__('Pinned values')) ?></b>:
                    <?= h(sprintf(__('%1$s of %2$s'), count($comparison_set),
                        $comparison_limit)) ?></span>
                <?php if (!empty($comparison_set)): ?>
                    <div class="dropdown">
                        <button type="button" class="btn btn-link btn-sm ap-health-act"
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
            </li>
        </ul>
    </div>
</section>
