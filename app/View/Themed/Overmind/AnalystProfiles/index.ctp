<?php
/**
 * Every profile this reader may see, under a banner saying which one
 * scores them and how it was reached.
 *
 * The commonest confusion this feature can create is an analyst editing
 * a profile that is not weighting their pages, so the banner walks the
 * resolution order and every row carries its own standing. A choice can
 * also stop resolving without anybody touching it — the profile is
 * deleted, or switched off — and the banner says so, because the row it
 * is about may no longer exist.
 *
 * @var array $profiles Every row, for the banner
 * @var array $shown The rows the filter bar leaves
 * @var array $scope_answers What each scope answers with
 * @var array|null $in_force
 * @var bool $scoring_off
 * @var array $unresolved Declarations that resolved to nothing
 * @var bool $may_select_for_org
 * @var bool $may_select_for_instance
 * @var array $loader_errors
 * @var array $comparison_set
 * @var int $comparison_limit
 * @var array $capabilities
 * @var array|null $shipped Site admins only
 */
App::uses('CakeTime', 'Utility');

echo $this->element('genericElements/assetLoader', array(
    'css' => array('value-palette', 'analyst-profile'),
    'js' => array('analyst-profile', 'analyst-profile-cards'),
));

$others = count(array_filter($profiles, function ($profile) {
    return $profile['scope_rank'] === 1;
}));

/*
 * The instance default is the row the site setting names, read whether
 * or not it resolved: when it is switched off, enabling *that* row is the
 * repair the banner offers.
 */
$default = $scope_answers['default'];
$answers = $scope_answers['answers'];
$wonBy = $scope_answers['won_by'];
$scopes = array(
    'user' => __('Yours'),
    'org' => __('Your organisation'),
    'instance' => __('Instance default'),
);

// Which scopes point at a row: the standing names only the winner.
$pointWord = array(
    'user' => __('your choice'),
    'org' => __('your organisation\'s'),
    'instance' => __('instance default'),
);

$canForkForOrg = !empty($me['Role']['perm_admin'])
    || !empty($me['Role']['perm_site_admin']);

$this->set('headerTitle', __('Analyst Profiles'));
$this->set('headerCount', count($profiles));
$this->set('headerDescription', __('A profile decides what MISP makes of'
    . ' a value: which evidence counts and for how long, which labels'
    . ' come first, and which enrichment modules may run. One is in'
    . ' force for you at a time.'));

$headerActions = [];
if ($default !== null) {
    $headerActions[] = [
        'type' => 'modal',
        'standalone' => true,
        'class' => 'btn btn-outline-primary',
        'size' => 'md',
        'label' => __('Fork the instance default'),
        'icon' => 'code-branch',
        'url' => $baseurl . '/analystProfiles/fork/' . $default['id'],
        'title' => sprintf(
            __('A copy of %s that you own and can edit.'),
            $default['name']
        ),
    ];
}
$headerActions[] = [
    'type' => 'modal',
    'label' => __('Import JSON'),
    'icon' => 'file-import',
    'url' => $baseurl . '/analystProfiles/import',
    'size' => 'lg',
    'title' => __("Somebody else's, exported from their instance."),
];
$this->set('headerActions', $headerActions);

/*
 * The first sentence of the description, and only that: the shipped six
 * say who the profile is for, then repeat the same boilerplate.
 */
$firstSentence = function ($description) {
    $line = trim(strtok($description, "\n"));
    if (preg_match('/^(.{20,}?[.!?])\s/u', $line . ' ', $m)) {
        $line = $m[1];
    }
    return $line;
};

$viewUrl = $baseurl . '/analystProfiles/view/%id%';

$fields = [
    [
        'name' => __('ID'),
        'data_path' => 'id',
        'element' => 'id',
        'url' => $viewUrl,
        'card_section' => 'top',
    ],
    [
        'name' => __('Name'),
        'element' => 'custom',
        'class' => 'ap-col-name',
        'card_section' => 'title',
        'function' => function ($profile) use ($pointWord, $firstSentence) {
            $out = '<div class="ap-name-line"><a class="ap-name fw-semibold"'
                . ' href="' . h($this->Html->url(array(
                    'action' => 'view', $profile['id']))) . '"'
                . ' title="' . h($profile['uuid']) . '">'
                . h($profile['name']) . '</a>';
            foreach ($pointWord as $scope => $word) {
                if (in_array($scope, $profile['selected_by'], true)) {
                    $out .= '<span class="ap-point">' . h($word) . '</span>';
                }
            }
            if (!empty($profile['unparseable'])) {
                $out .= '<span class="pill t-missing">'
                    . h(__('document will not parse')) . '</span>';
            }
            $out .= '</div>';
            if (!empty($profile['description'])) {
                $line = $firstSentence($profile['description']);
                $out .= '<div class="ap-desc" title="' . h($line) . '">'
                    . h($line) . '</div>';
            }
            return $out;
        },
    ],
    [
        'name' => __('Owner'),
        'data_path' => 'owner',
        'class' => 'text-nowrap',
        'card_section' => 'meta',
    ],
    [
        'name' => __('Standing'),
        'element' => 'custom',
        'card_section' => 'top',
        'function' => function ($profile) {
            return $this->element('AnalystProfiles/standing',
                array('profile' => $profile));
        },
    ],
    [
        'name' => __('Version'),
        'element' => 'custom',
        'card_section' => 'top',
        /*
         * Only on a profile MISP ships: a fork is born at version 1 and
         * stays there, so the number says nothing about it.
         */
        'function' => function ($profile) {
            if (empty($profile['default'])) {
                return '<span class="text-body-secondary">&mdash;</span>';
            }
            $out = $this->element('genericElementsBS5/Badges/version',
                array('version' => (int)$profile['version']));
            if ($profile['edited_here']) {
                $out .= ' <span class="ap-edited" title="' . h(__(
                    'Changed on this instance since MISP last wrote it.'
                    . ' The next shipped update replaces the change.'))
                    . '">' . h(__('edited here')) . '</span>';
            }
            return $out;
        },
    ],
    [
        'name' => __('Signals on'),
        'element' => 'custom',
        'card_section' => 'meta',
        'function' => function ($profile) {
            $on = (int)$profile['signals']['enabled'];
            $of = (int)$profile['signals']['configured'];
            if ($of === 0) {
                return '<span class="text-body-secondary">&mdash;</span>';
            }
            $percent = (int)round($on / $of * 100);
            return '<div class="ap-signals" title="' . h(sprintf(
                    __('%s of the %s signals this profile configures are'
                        . ' switched on'), $on, $of)) . '">'
                . '<div class="d-flex align-items-baseline gap-1 lh-1">'
                . '<span class="fw-semibold">' . h($on) . '</span>'
                . '<span class="text-body-secondary small">/ ' . h($of)
                . '</span></div>'
                . '<div class="progress mt-1" style="height: 4px;"'
                . ' role="progressbar" aria-valuenow="' . $percent . '"'
                . ' aria-valuemin="0" aria-valuemax="100">'
                . '<div class="progress-bar" style="width: ' . $percent
                . '%;"></div></div></div>';
        },
    ],
    [
        'name' => __('Changed'),
        'element' => 'custom',
        'card_section' => 'meta',
        // One unit at every magnitude, so the column never wraps.
        'function' => function ($profile) {
            return '<span class="text-body-secondary text-nowrap" title="'
                . h($profile['modified']) . '">'
                . h(CakeTime::timeAgoInWords($profile['modified'], array(
                    'accuracy' => array(
                        'year' => 'year',
                        'month' => 'month',
                        'week' => 'week',
                        'day' => 'day',
                        'hour' => 'hour',
                        'minute' => 'minute',
                    ),
                ))) . '</span>';
        },
    ],
    [
        'name' => __('Actions'),
        'element' => 'custom',
        'class' => 'text-end',
        'card_section' => 'extra',
        'function' => function ($profile) use (
            $may_select_for_org, $may_select_for_instance, $canForkForOrg
        ) {
            return $this->element('AnalystProfiles/row_actions', array(
                'profile' => $profile,
                'may_select_for_org' => $may_select_for_org,
                'may_select_for_instance' => $may_select_for_instance,
                'can_fork_for_org' => $canForkForOrg,
            ));
        },
    ],
];

$ownerOptions = array(
    'misp' => __('Shipped by MISP'),
    'mine' => __('Yours'),
    'org' => __('Your organisation'),
    'shared' => __('Shared'),
);
$standingOptions = array(
    'in_force' => __('In force'),
    'overridden' => __('Overridden'),
    'not_selected' => __('Not chosen'),
    'disabled' => __('Not in use'),
);
if ($others > 0) {
    $ownerOptions['other'] = __('Other owners');
    $standingOptions['other_owner'] = __('Another owner');
}

$banner = $this->element('AnalystProfiles/loader_errors', array(
        'loader_errors' => $loader_errors,
    ))
    . $this->element('AnalystProfiles/where_you_stand', array(
        'in_force' => $in_force,
        'scoring_off' => $scoring_off,
        'default' => $default,
        'scopes' => $scopes,
        'answers' => $answers,
        'won_by' => $wonBy,
        'unresolved' => $unresolved,
        'capabilities' => $capabilities,
        'may_select_for_instance' => $may_select_for_instance,
        'comparison_set' => $comparison_set,
        'comparison_limit' => $comparison_limit,
        'shipped' => $shipped,
    ));
?>
<div class="ap-page">
    <?= $this->element('genericElementsBS5/IndexTable/scaffold', [
        'scaffold_data' => [
            'data' => [
                'data' => $shown,
                'cards_per_row' => ['' => 1, 'lg' => 2, 'xxxxl' => 3],
                'before_filter_bar' => $banner,
                'filter_bar' => [
                    'skip_pagination' => true,
                    'children' => [
                        [
                            'type' => 'search',
                            'button' => __('Search'),
                            'placeholder' => __('Search by name, owner or UUID'),
                            'mode' => 'quickFilter',
                        ],
                        [
                            'type' => 'more_filters',
                            'label' => __('More filters'),
                            'children' => [
                                [
                                    'type' => 'dropdown',
                                    'label' => __('Owner'),
                                    'name' => 'owner',
                                    'separator' => '||',
                                    'options' => ['' => ''] + $ownerOptions,
                                ],
                                [
                                    'type' => 'dropdown',
                                    'label' => __('Standing'),
                                    'name' => 'standing',
                                    'separator' => '||',
                                    'options' => ['' => ''] + $standingOptions,
                                ],
                            ],
                        ],
                    ],
                ],
                'fields' => $fields,
                'primary_id_path' => 'id',
                'row_dblclick_url' => $viewUrl,
                'row_class_callable' => function ($profile) {
                    return $profile['in_force'] ? 'ap-row-inforce' : '';
                },
                'skip_pagination' => true,
                'empty_message' => __('No profile matches these filters.'),
            ],
        ],
        'item_url' => '/analystProfiles',
    ]) ?>
</div>

<?php
/*
 * Outside `.ap-page`: a query container is the containing block of its
 * fixed descendants, and the modal has to sit on the viewport.
 */
?>
<div class="modal fade ap-enrich-modal" id="ap-enrichment-modal" tabindex="-1"
     aria-labelledby="ap-enrichment-title" aria-hidden="true"
     data-ap-fix-url="<?= h($this->Html->url(array('action' => 'fix'))) ?>"
     data-ap-load-failed="<?= h(__('This could not be loaded. Reload the page'
         . ' to try again.')) ?>"
     data-ap-unchecked="<?= h(__('could not be checked')) ?>"
     data-ap-fix-failed="<?= h(__('That could not be switched on. The'
         . ' settings page says why.')) ?>">
    <div class="modal-dialog modal-dialog-scrollable <?=
        $may_select_for_instance ? 'modal-xl' : 'modal-lg' ?>">
        <div class="modal-content">
            <div class="modal-header">
                <h2 class="modal-title fs-5" id="ap-enrichment-title"><?= h(
                    $may_select_for_instance
                        ? __('What the profiles ask for')
                        : __('Your enrichment')) ?></h2>
                <button type="button" class="btn-close" data-bs-dismiss="modal"
                        aria-label="<?= h(__('Close')) ?>"></button>
            </div>
            <div class="modal-body" data-ap-card-src="<?= h($this->Html->url(
                array('action' => 'enrichment'))) ?>">
                <?= $this->element('genericElementsBS5/loader', array(
                    'size' => 'sm',
                    'label' => __('Asking the modules service'),
                )) ?>
            </div>
        </div>
    </div>
</div>
