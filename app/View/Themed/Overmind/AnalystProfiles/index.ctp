<?php
/**
 * Every profile this reader may see, with the one in force named
 * first and unmistakably.
 *
 * The commonest confusion this feature can create is an analyst
 * editing a profile that is not weighting their pages — they forked,
 * forgot, and their organisation's still wins, or their own is
 * disabled. So the rail is the resolution order and every row carries
 * its own standing, which is computed rather than drawn.
 *
 * Since D45 there is a second way to be confused, and it is the one
 * MISP creates by shipping six profiles: a reader may have *chosen* a
 * profile rather than forked one, and a choice can stop resolving
 * without anybody touching it — the profile is deleted, or switched
 * off. `$unresolved` is that, and it is drawn above the table rather
 * than on a row, because the row it is about may no longer exist.
 *
 * The right column is the reader's own standing rather than a tool:
 * what scores them, what this instance permits, and what travels with
 * them into the editor. Its three blocks are all *answers about this
 * visit*, which is the one thing the table's rows cannot be.
 *
 * @var array $profiles
 * @var array|null $in_force
 * @var bool $scoring_off
 * @var string|null $via How the profile in force was reached
 * @var array $selections The uuid each scope declares
 * @var array $unresolved Declarations that resolved to nothing
 * @var bool $may_select_for_org
 * @var bool $may_select_for_instance
 * @var array $loader_errors
 * @var array $comparison_set
 * @var int $comparison_limit
 * @var array $capabilities
 */
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');
App::uses('CakeTime', 'Utility');

echo $this->element('genericElements/assetLoader', array(
    'css' => array('value-palette', 'analyst-profile'),
    'js' => array('analyst-profile'),
));

/*
 * What each scope answers with.
 *
 * The rail used to count the rows a scope *owns*, which is a different
 * question and gives a different number: MISP's six shipped profiles
 * carry no `user_id` and no `org_id`, so an organisation that has
 * *chosen* one owns nothing, counted zero, and read as having no answer
 * on the very page whose winning row said *Your organisation chose it*.
 * Ownership is one of the two ways a scope answers (D45) and the rail
 * is headed *resolution order*, so it reports the answer itself.
 *
 * The order here is `resolutionFor()`'s: an owned enabled profile
 * first, then the uuid the scope declared, and a declaration that did
 * not resolve is a reason rather than a name. The instance owns
 * nothing ever — it names one.
 */
$byUuid = array();
$ownedBy = array('user' => null, 'org' => null, 'instance' => null);
$others = 0;
foreach ($profiles as $profile) {
    $byUuid[$profile['uuid']] = $profile;
    if ($profile['scope_rank'] === 1) {
        $others++;
    }
    if (!empty($profile['enabled'])) {
        if ($profile['scope_rank'] === 3 && $ownedBy['user'] === null) {
            $ownedBy['user'] = $profile;
        } elseif ($profile['scope_rank'] === 2 && $ownedBy['org'] === null) {
            $ownedBy['org'] = $profile;
        }
    }
}

/*
 * The instance default: the one row the site setting names.
 *
 * This used to be *the last row in the list carrying `default = 1`*,
 * which was a single row until MISP shipped six of them and is now an
 * arbitrary one. It put the wrong name in *Fork the instance default*
 * and pointed *Enable the instance default* — the one button offered
 * when nothing is in force — at a profile whose being enabled would fix
 * nothing.
 *
 * Read whether or not it resolved, because the state that most needs it
 * is the one where it did not: the named row is switched off, and
 * enabling *that* row is the repair.
 */
$default = !empty($selections['instance'])
    && isset($byUuid[$selections['instance']])
        ? $byUuid[$selections['instance']]
        : null;

$scopes = array(
    'user' => __('Yours'),
    'org' => __('Your organisation'),
    'instance' => __('Instance default'),
);
// `via` is `user`, `org`, `instance`, or one of the `_selection` pair.
$wonBy = $via === null ? null : preg_replace('/_selection$/', '', $via);
$answers = array();
foreach ($scopes as $scope => $label) {
    $answer = array('profile' => null, 'reason' => null);
    if ($ownedBy[$scope] !== null) {
        $answer['profile'] = $ownedBy[$scope];
    } elseif (isset($unresolved[$scope])) {
        $answer['reason'] = $unresolved[$scope]['reason'];
    } elseif (!empty($selections[$scope])
        && isset($byUuid[$selections[$scope]])
    ) {
        $answer['profile'] = $byUuid[$selections[$scope]];
    }
    $answers[$scope] = $answer;
}
/*
 * The rail's relation, seen from the row: *which scopes point here?*
 *
 * The rail answers scope → profile and a reader arriving at a row has
 * the opposite question. It cannot be read off the standing, which
 * reports only the winner: with an organisation's choice in force, the
 * instance default is merely *overridden*, and which of the five other
 * shipped profiles it is is not on the row at all.
 */
$pointWord = array(
    'user' => __('your choice'),
    'org' => __('your organisation\'s'),
    'instance' => __('instance default'),
);
$railReason = array(
    'missing' => __('the profile it named is gone'),
    'disabled' => __('the profile it named is switched off'),
    'unreadable' => __('it may not use the profile it named'),
);

$canForkForOrg = !empty($me['Role']['perm_admin'])
    || !empty($me['Role']['perm_site_admin']);

$create = array();
if ($default !== null) {
    $create[] = array(
        'type' => 'action',
        'label' => __('Fork the instance default'),
        'icon' => 'code-branch',
        'url' => array('action' => 'fork', $default['id']),
        'title' => sprintf(
            __('A copy of %s that you own and can edit.'),
            $default['name']
        ),
    );
}
$create[] = array(
    'type' => 'navigate',
    'label' => __('Import JSON'),
    'icon' => 'file-import',
    'url' => array('action' => 'import'),
    'title' => __("Somebody else's, exported from their instance."),
);

$this->set('headerTitle', __('Analyst Profiles'));
$this->set('headerBreadcrumb', __('Analyst Profiles'));
$this->set('headerCount', count($profiles));
/*
 * All three of a document's jobs, because naming only the first sends
 * a reader looking for the label order and the module list somewhere
 * else: `signals`/`thresholds`/`relevance` weigh, `context` orders what
 * the page shows first, and `enrichment` says what may run.
 */
$this->set('headerDescription', __('A profile decides what MISP makes of'
    . ' a value: which evidence counts and for how long, which labels'
    . ' come first, and which enrichment modules may run. One is in'
    . ' force for you at a time.'));
$this->set('headerActions', array(array(
    'type' => 'dropdown',
    'label' => __('New profile'),
    'icon' => 'plus',
    'class' => 'btn btn-outline-primary',
    'children' => $create,
)));
?>

<div class="ap-page">
    <div class="container-fluid">
        <?= $this->element('AnalystProfiles/loader_errors', array(
            'loader_errors' => $loader_errors,
        )) ?>

        <div class="wb wb-index">
            <div class="wb-panehead wb-panehead-left">
                <span><?= h(__('The profiles')) ?></span>
                <em><?= h(__('the first enabled one wins')) ?></em>
            </div>
            <div class="wb-panehead wb-panehead-right">
                <span><?= h(__('Where you stand')) ?></span>
            </div>

            <nav class="wb-rail" data-tour="ap-resolution">
                <div class="wb-rail-title"><?= h(__('Resolution order')) ?></div>
                <?php $step = 1; ?>
                <?php foreach ($scopes as $scope => $label): ?>
                    <?php $answer = $answers[$scope]; ?>
                    <div class="wb-rail-item wb-rail-step<?=
                        $wonBy === $scope ? ' is-open' : '' ?>">
                        <span class="s"><?= h($step++) ?></span>
                        <span class="t">
                            <span class="l"><?= h($label) ?></span>
                            <?php if ($answer['profile'] !== null): ?>
                                <span class="a"><a href="<?= h(
                                    $this->Html->url(array('action' => 'view',
                                        $answer['profile']['id']))) ?>"><?= h(
                                    $answer['profile']['name']) ?></a></span>
                            <?php elseif ($answer['reason'] !== null): ?>
                                <span class="a warn"><?= h(
                                    isset($railReason[$answer['reason']])
                                        ? $railReason[$answer['reason']]
                                        : $answer['reason']) ?></span>
                            <?php else: ?>
                                <span class="a none"><?= h(
                                    __('no answer')) ?></span>
                            <?php endif; ?>
                        </span>
                    </div>
                <?php endforeach; ?>
                <?php if ($others > 0): ?>
                    <?php
                    /*
                     * Not a step: rows belonging to somebody a site
                     * admin can see and no scope of theirs can resolve.
                     * A count is all it is, so it keeps one.
                     */
                    ?>
                    <div class="wb-rail-item wb-rail-aside">
                        <span><?= h(__('Other owners')) ?></span>
                        <span class="c"><?= h($others) ?></span>
                    </div>
                <?php endif; ?>
                <p class="wb-rail-note">
                    <?= $scoring_off
                        ? h(__('None of the three answers, so nothing on'
                            . ' this instance is scored for you.'))
                        : h(__('MISP asks these three in order and takes the'
                            . ' first answer, marked above.')) ?>
                </p>
                <?php
                /*
                 * Said once, here, rather than on each of the five rows
                 * that stand *not chosen*: choosing and forking are
                 * different verbs and the difference is not visible from
                 * either button.
                 */
                ?>
                <p class="wb-rail-note">
                    <?= h(__('Choosing a profile MISP ships keeps it up to'
                        . ' date as MISP corrects it. Forking freezes a copy'
                        . ' you own and can edit.')) ?>
                </p>
            </nav>

            <div class="wb-body">
                <?php if (!empty($unresolved)): ?>
                    <?php
                    /*
                     * A choice that stopped resolving. Drawn here and not
                     * on a row because the profile it names may have been
                     * deleted, and a reader whose page is suddenly scored
                     * by something else has no other way to find out why.
                     */
                    $scopeWord = array(
                        'user' => __('Your choice'),
                        'org' => __('Your organisation\'s choice'),
                        'instance' => __('The instance\'s choice'),
                    );
                    $reasonWord = array(
                        'missing' => __('names a profile that is no longer'
                            . ' on this instance'),
                        'disabled' => __('names a profile that has been'
                            . ' switched off'),
                        'unreadable' => __('names a profile this scope may'
                            . ' not use'),
                    );
                    ?>
                    <?php foreach ($unresolved as $scope => $problem): ?>
                        <p class="wb-note warn mb-2">
                            <?= h(sprintf(
                                __('%1$s %2$s (%3$s). The next scope is'
                                    . ' answering instead.'),
                                isset($scopeWord[$scope])
                                    ? $scopeWord[$scope] : $scope,
                                isset($reasonWord[$problem['reason']])
                                    ? $reasonWord[$problem['reason']]
                                    : $problem['reason'],
                                isset($problem['name'])
                                    ? $problem['name']
                                    : substr($problem['uuid'], 0, 8)
                            )) ?>
                        </p>
                    <?php endforeach; ?>
                <?php endif; ?>
                <table class="wb-tbl ap-index-tbl" data-tour="ap-profiles">
                    <thead>
                        <tr>
                            <th style="width:38%"><?= h(__('Profile')) ?></th>
                            <th><?= h(__('Standing')) ?></th>
                            <th style="width:10%"
                                title="<?= h(__('Signals switched on, of the'
                                    . ' signals this profile configures')) ?>">
                                <?= h(__('Signals on')) ?></th>
                            <th style="width:12%"><?= h(__('Last change')) ?></th>
                            <th style="width:8%"></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($profiles as $profile): ?>
                            <tr class="<?= $profile['in_force'] ? 'is-hot' : '' ?>">
                                <td>
                                    <div class="fw-semibold">
                                        <a class="ap-name" href="<?= h(
                                            $this->Html->url(array(
                                                'action' => 'view',
                                                $profile['id']))) ?>"><?= h(
                                            $profile['name']) ?></a>
                                        <?php foreach ($pointWord
                                            as $scope => $word): ?>
                                            <?php if (in_array($scope,
                                                $profile['selected_by'],
                                                true)): ?>
                                                <span class="ap-point"><?= h(
                                                    $word) ?></span>
                                            <?php endif; ?>
                                        <?php endforeach; ?>
                                    </div>
                                    <div class="wb-sub">
                                        <?= h($profile['owner']) ?> &middot;
                                        <span class="wb-id"><?= h(substr(
                                            $profile['uuid'], 0, 8)) ?></span>
                                        <?php
                                        /*
                                         * The shipped document's version,
                                         * and whether this copy still
                                         * matches it. Only on a profile MISP
                                         * ships: a fork is born at version 1
                                         * and stays there, so the number
                                         * says nothing about it, and
                                         * `revision` is a cache key rather
                                         * than something to read.
                                         */
                                        ?>
                                        <?php if (!empty($profile['default'])): ?>
                                            &middot;
                                            <span class="wb-id"
                                                  title="<?= h(sprintf(
                                                      __('Shipped document'
                                                          . ' version %1$s,'
                                                          . ' edited %2$s'
                                                          . ' times here'),
                                                      $profile['version'],
                                                      $profile['revision']
                                                  )) ?>">v<?= h(
                                                $profile['version']) ?></span>
                                            <?php if ($profile['revision'] > 1): ?>
                                                &middot; <?= h(
                                                    __('edited here')) ?>
                                            <?php endif; ?>
                                        <?php endif; ?>
                                    </div>
                                    <?php if (!empty($profile['description'])): ?>
                                        <?php
                                        /*
                                         * The first sentence, and only that.
                                         *
                                         * A fork carries its origin line and
                                         * then whatever the source said,
                                         * which on the shipped six is a
                                         * paragraph: one sentence saying who
                                         * the profile is for, then the same
                                         * boilerplate about carrying the
                                         * default's weights on every one of
                                         * them. Cutting at a character count
                                         * kept the boilerplate and cut the
                                         * sentence; cutting at the full stop
                                         * keeps the half that differs.
                                         */
                                        $line = trim(strtok(
                                            $profile['description'], "\n"));
                                        if (preg_match('/^(.{20,}?[.!?])\s/u',
                                            $line . ' ', $m)
                                        ) {
                                            $line = $m[1];
                                        }
                                        /*
                                         * `.{140}.` under `/u` matches only
                                         * a line with a 141st character, and
                                         * counts characters rather than
                                         * bytes — so the cut never lands
                                         * inside one. PCRE rather than
                                         * `mb_substr()` because the PRD's
                                         * render harnesses run on a CLI PHP
                                         * without mbstring, and a template
                                         * they cannot include is a template
                                         * nothing checks.
                                         */
                                        if (preg_match('/^(.{140})./u',
                                            $line, $m)
                                        ) {
                                            $line = $m[1];
                                            $cut = strrpos($line, ' ');
                                            if ($cut !== false && $cut > 60) {
                                                $line = substr($line, 0, $cut);
                                            }
                                            $line = rtrim($line, " ,;:") . '…';
                                        }
                                        ?>
                                        <div class="wb-sub mt-1"><?= h($line) ?></div>
                                    <?php endif; ?>
                                    <?php if (!empty($profile['unparseable'])): ?>
                                        <div class="mt-1">
                                            <span class="pill t-missing"><?= h(
                                                __('document will not parse')
                                            ) ?></span>
                                        </div>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?= $this->element('AnalystProfiles/standing',
                                        array('profile' => $profile)) ?>
                                </td>
                                <td class="num">
                                    <?= h($profile['signals']['enabled']) ?>&nbsp;/&nbsp;<?= h(
                                        $profile['signals']['configured']) ?>
                                </td>
                                <td class="wb-sub ap-when">
                                    <?php
                                    /*
                                     * One unit, at every magnitude. The
                                     * default shows two past an hour — *1
                                     * hour, 31 minutes ago* — and the second
                                     * one wraps this column onto a second
                                     * line to answer a question nobody scans
                                     * this column for. The timestamp stays,
                                     * on hover.
                                     */
                                    ?>
                                    <span title="<?= h($profile['modified']) ?>">
                                        <?= h(CakeTime::timeAgoInWords(
                                            $profile['modified'],
                                            array('accuracy' => array(
                                                'year' => 'year',
                                                'month' => 'month',
                                                'week' => 'week',
                                                'day' => 'day',
                                                'hour' => 'hour',
                                                'minute' => 'minute',
                                            ))
                                        )) ?></span>
                                </td>
                                <td>
                                    <?= $this->element('AnalystProfiles/row_actions',
                                        array(
                                            'profile' => $profile,
                                            'in_force' => $in_force,
                                            'may_select_for_org' =>
                                                $may_select_for_org,
                                            'may_select_for_instance' =>
                                                $may_select_for_instance,
                                            'can_fork_for_org' => $canForkForOrg,
                                        )) ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <aside class="wb-bench" data-tour="ap-standing">
                <div class="wb-bench-inner">
                    <?php if ($scoring_off): ?>
                        <div class="wb-empty">
                            <div class="fw-semibold"><?= h(__('Nothing in force')) ?></div>
                            <p class="mb-1 mt-1">
                                <?= h(__('No profile applies to you, so nothing'
                                    . ' on this instance is scored. Value pages'
                                    . ' still show their evidence; none of them'
                                    . ' shows a signal strength.')) ?>
                            </p>
                            <?php if ($default !== null && !$default['enabled']): ?>
                                <?php
                                /*
                                 * Named, because this button is the
                                 * repair and a reader about to press it
                                 * should see which profile it switches
                                 * on. Offered only where that row is
                                 * the one switched off — enabling an
                                 * already-enabled instance default
                                 * fixes nothing and is not the reason
                                 * scoring is off.
                                 */
                                ?>
                                <?= $this->Form->postLink(
                                    sprintf(__('Enable %s'), $default['name']),
                                    array('action' => 'enable', $default['id']),
                                    array('class' => 'btn btn-sm'
                                        . ' btn-outline-primary py-0 px-2 mt-1')
                                ) ?>
                            <?php endif; ?>
                        </div>
                    <?php else: ?>
                        <div class="bench-sec">
                            <span><?= h(__('Scoring you')) ?></span>
                        </div>
                        <p class="mt-1 mb-2 ap-inforce">
                            <a class="fw-semibold" href="<?= h(
                                $this->Html->url(array('action' => 'view',
                                    $in_force['id']))) ?>"><?= h(
                                $in_force['name']) ?></a>
                            <?= h(__('scores every value page you open, until'
                                . ' you choose or enable another.')) ?>
                        </p>
                    <?php endif; ?>

                    <?= $this->element('AnalystProfiles/instance_state', array(
                        'capabilities' => $capabilities,
                        'may_select_for_instance' => $may_select_for_instance,
                    )) ?>

                    <div class="bench-sec">
                        <span><?= h(__('Values you pinned')) ?></span>
                        <span class="num"><?= h(sprintf(
                            __('%1$s of %2$s'),
                            count($comparison_set),
                            $comparison_limit
                        )) ?></span>
                    </div>
                    <?php if (empty($comparison_set)): ?>
                        <p class="wb-sub mt-1 mb-0">
                            <?= h(__('Pin a value while editing a profile and'
                                . ' it follows you between profiles, so every'
                                . ' change is judged on the same value. You'
                                . ' pin from a profile, not from here.')) ?>
                        </p>
                    <?php else: ?>
                        <p class="wb-sub mt-1 mb-2">
                            <?= h(__('These follow you into every profile you'
                                . ' open, so a change is judged on the same'
                                . ' values each time.')) ?>
                        </p>
                        <table class="wb-tbl">
                            <tbody>
                                <?php foreach ($comparison_set as $value): ?>
                                    <tr>
                                        <td class="wb-id"><?= h($value) ?></td>
                                        <td class="r wb-sub">
                                            <?= $this->Form->postLink(
                                                __('unpin'),
                                                array('action' => 'unpin',
                                                    ValueUrlTool::encode($value)),
                                                array('class' => 'wb-sub')
                                            ) ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>
            </aside>
        </div>
    </div>
</div>
