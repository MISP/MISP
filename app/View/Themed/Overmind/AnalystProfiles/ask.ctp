<?php
/**
 * The modal a row menu opens before a profile write, in the shared
 * confirmation chrome. Its form posts back to the address it was loaded
 * from, which carries the scope.
 *
 * @var array $ask `verb`, and as it applies: `scope`, `profile`,
 *      `in_force`, `displaced`, `replaces`, `affects`, `owned`, `url`
 */
$verb = $ask['verb'];
$scope = isset($ask['scope']) ? $ask['scope'] : null;
$name = isset($ask['profile']['name']) ? $ask['profile']['name'] : null;
$displaced = isset($ask['displaced']) ? $ask['displaced'] : null;
$warning = array();
$note = null;

if (!empty($ask['affects'])) {
    $note = __n(
        'It changes how values are scored for %1$s of the %2$s people in'
            . ' your organisation: those without a profile of their own.',
        'It changes how values are scored for %1$s of the %2$s people in'
            . ' your organisation: those without a profile of their own.',
        $ask['affects']['affected'],
        $ask['affects']['affected'],
        $ask['affects']['users']
    );
}

if ($verb === 'use' && $scope === 'user') {
    $options = array(
        'title' => __('Use for me'),
        'message' => empty($ask['in_force'])
            ? sprintf(__('%s will score every value page you open.'), $name)
            : sprintf(__('%1$s will score every value page you open,'
                . ' instead of %2$s.'), $name, $ask['in_force']),
        'submitLabel' => __('Use for me'),
        'submitIcon' => 'user-check',
        'accent' => 'primary',
    );
    if ($displaced !== null) {
        $warning[] = sprintf(__('%s, your own profile, stops being used. It'
            . ' is kept, not deleted.'), $displaced);
    }
} elseif ($verb === 'use') {
    $options = array(
        'title' => __('Use for my organisation'),
        'message' => sprintf(__('%s will score every colleague who has not'
            . ' chosen or forked a profile of their own.'), $name),
        'submitLabel' => __('Use for my organisation'),
        'submitIcon' => 'building-circle-check',
        'accent' => 'warning',
    );
    if ($displaced !== null) {
        $warning[] = sprintf(__('%s, your organisation\'s own profile, stops'
            . ' being used. It is kept, not deleted.'), $displaced);
    }
} elseif ($verb === 'stop' && $scope === 'user') {
    $options = array(
        'title' => __('Stop using for me'),
        'message' => $name === null
            ? __('Your own choice is cleared. Your organisation\'s profile'
                . ' scores your pages instead, or the instance default when'
                . ' it has none.')
            : sprintf(__('%s stops scoring your pages. Your organisation\'s'
                . ' profile scores them instead, or the instance default when'
                . ' it has none.'), $name),
        'submitLabel' => __('Stop using'),
        'submitIcon' => 'user-xmark',
        'accent' => 'primary',
    );
} elseif ($verb === 'stop') {
    $options = array(
        'title' => __('Stop using for my organisation'),
        'message' => $name === null
            ? __('Your organisation\'s choice is cleared. Colleagues who have'
                . ' not chosen or forked a profile of their own fall back to'
                . ' the instance default.')
            : sprintf(__('Your organisation stops using %s. Colleagues who'
                . ' have not chosen or forked a profile of their own fall back'
                . ' to the instance default.'), $name),
        'submitLabel' => __('Stop using'),
        'submitIcon' => 'building-circle-xmark',
        'accent' => 'warning',
    );
} elseif ($verb === 'run') {
    $options = array(
        'title' => __('Run on this instance'),
        'message' => sprintf(__('%s will score every reader whose'
            . ' organisation and account have chosen none.'), $name),
        'submitLabel' => __('Run on this instance'),
        'submitIcon' => 'server',
        'accent' => 'warning',
    );
    if (!empty($ask['replaces'])) {
        $warning[] = sprintf(__('It replaces %s as the instance profile.'),
            $ask['replaces']);
    }
} elseif ($verb === 'fork') {
    $options = array(
        'title' => $scope === 'org'
            ? __('Fork to my organisation')
            : __('Fork to me'),
        'message' => sprintf(
            $scope === 'org'
                ? __('Fork %s into a copy your organisation owns and can'
                    . ' edit. The copy scores every colleague who has not'
                    . ' chosen or forked a profile of their own.')
                : __('Fork %s into a copy you own and can edit. The copy'
                    . ' scores your pages from now on.'),
            $name
        ),
        'submitLabel' => __('Fork'),
        'submitIcon' => 'code-branch',
        'accent' => $scope === 'org' ? 'warning' : 'primary',
        'hint' => empty($ask['profile']['default']) ? '' : __('A fork stops'
            . ' following MISP\'s corrections; choosing the shipped profile'
            . ' keeps them coming.'),
    );
    if ($displaced !== null) {
        $warning[] = sprintf(
            $scope === 'org'
                ? __('%s, your organisation\'s own profile, stops being used.'
                    . ' It is kept, not deleted.')
                : __('%s, your own profile, stops being used. It is kept,'
                    . ' not deleted.'),
            $displaced
        );
    }
} elseif ($verb === 'share') {
    $options = array(
        'title' => __('Share with everyone'),
        'message' => sprintf(__('Every user can read, fork and choose %s, and'
            . ' your edits reach everyone who chose it.'), $name),
        'submitLabel' => __('Share'),
        'submitIcon' => 'share-nodes',
        'accent' => 'primary',
    );
    $warning[] = __('It stops being your own profile.');
} elseif ($verb === 'unshare') {
    $options = array(
        'title' => __('Stop sharing'),
        'message' => sprintf(__('Readers who chose %s fall back to their next'
            . ' profile.'), $name),
        'submitLabel' => __('Stop sharing'),
        'submitIcon' => 'share-nodes',
        'accent' => 'warning',
    );
    $warning[] = __('It comes back to you, not in use.');
} elseif ($verb === 'delete') {
    $options = array(
        'title' => __('Delete'),
        'message' => sprintf(__('Delete %s? A profile is a tuned judgement and'
            . ' this cannot be undone.'), $name),
        'submitLabel' => __('Delete'),
        'submitIcon' => 'trash',
        'accent' => 'danger',
        'hint' => __('Stop using it instead to keep it.'),
    );
} elseif ($verb === 'load') {
    $options = array(
        'title' => __('Load shipped profiles'),
        'message' => sprintf(__n(
            '%s profile MISP ships is new or has changed: %s.',
            '%s profiles MISP ships are new or have changed: %s.',
            count($ask['loadable'])
        ), count($ask['loadable']), implode(', ', $ask['loadable'])),
        'submitLabel' => __('Load'),
        'submitIcon' => 'box-open',
        'accent' => 'primary',
        'hint' => __('Forks are never touched.'),
    );
    if (empty($ask['loadable'])) {
        $options['message'] = __('Every profile MISP ships is loaded and'
            . ' current.');
        $options['canProceed'] = false;
    }
    if (!empty($ask['overwrites'])) {
        $warning[] = __n(
            '%s was edited here, and loading replaces the edit.',
            '%s were edited here, and loading replaces the edits.',
            count($ask['overwrites']),
            implode(', ', $ask['overwrites'])
        );
    }
} elseif ($verb === 'switch_on') {
    $options = array(
        'title' => __('Switch on'),
        'message' => sprintf(__('Switch %s on, so it can be chosen again.'),
            $name),
        'submitLabel' => __('Switch on'),
        'submitIcon' => 'power-off',
        'accent' => 'primary',
    );
} else {
    $options = array(
        'title' => __('Switch off'),
        'message' => sprintf(__('Switch %s off for everybody? Nobody can choose'
            . ' it, and whoever relies on it falls back to their next'
            . ' profile.'), $name),
        'submitLabel' => __('Switch off'),
        'submitIcon' => 'power-off',
        'accent' => 'warning',
    );
}

if (!empty($ask['owned']) && $verb === 'stop') {
    $options['hint'] = __('It is kept: you can use it again at any time.');
}

echo $this->element('genericElementsBS5/Modals/confirmation_form', $options + array(
    'model' => 'AnalystProfile',
    'url' => isset($ask['url'])
        ? $this->Html->url($ask['url'])
        : $this->request->here(false),
    'hiddenField' => false,
    'eyebrow' => __('Analyst Profiles'),
    'description' => $name === null ? '' : $name,
    'warning' => $warning,
    'bodyHtml' => $note === null ? ''
        : '<p class="mb-0 small text-body-secondary">' . h($note) . '</p>',
));
