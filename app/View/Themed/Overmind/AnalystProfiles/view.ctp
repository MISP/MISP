<?php
/**
 * A profile, read-only.
 *
 * The same two panes as the editor with the inputs replaced by what
 * they hold. Not disabled inputs: a disabled input still looks like
 * something you could have changed, and this page is for a profile
 * that is somebody else's.
 *
 * With `?value=` each weight is shown beside the contribution it
 * produced on that value. Without one the column stays empty rather
 * than inventing a number.
 *
 * @var array $profile
 * @var bool $editable Whether this page is an editor. Always false here.
 * @var bool $may_edit Whether this reader would be allowed to edit it
 * @var bool $may_share A site admin's own profile, which they may share
 * @var array $bench
 */
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');

echo $this->element('genericElements/assetLoader', array(
    'css' => array('value-palette', 'analyst-profile'),
    'js' => array('analyst-profile', 'analyst-profile-help'),
));

$focus = $bench['focus'];
$query = $focus === null
    ? array()
    : array('value' => ValueUrlTool::encode($focus));

$actions = array(
    array(
        'type' => 'navigate',
        'label' => __('Simulate'),
        'icon' => 'flask',
        'url' => $this->Html->url(array(
            'action' => 'simulate', $profile['id'], '?' => $query)),
    ),
    array(
        'type' => 'navigate',
        'label' => __('Export'),
        'icon' => 'file-export',
        'url' => $this->Html->url(array('action' => 'export', $profile['id'])),
    ),
);
/*
 * `may_edit`, not `editable`. The second is *is this page an editor*,
 * which is false here by construction — so branching on it offered the
 * fork to everybody, and a reader looking at their own profile had the
 * browser's back button as the way to go and change it.
 *
 * The value travels with the link: a reader who arrived here to see
 * what this profile makes of one value wants to edit it against that
 * same value, not against a blank bench.
 */
if ($may_edit) {
    $actions[] = array(
        'type' => 'navigate',
        'label' => __('Edit'),
        'icon' => 'pen',
        'class' => 'btn btn-primary',
        'url' => $this->Html->url(array(
            'action' => 'edit', $profile['id'], '?' => $query)),
    );
}
/*
 * Forking stays offered either way, as it is on every index row: it is
 * how a variant of something that already works gets made, and wanting
 * one does not mean you could not have edited the original.
 *
 * It is the primary button only when there is no Edit to be it. For a
 * profile you cannot edit, forking is the one way in — there is no
 * blank form, since an empty `parameters` names no signal and scores
 * nothing.
 */
$fork = array(
    'type' => 'action',
    'label' => __('Fork to me'),
    'icon' => 'code-branch',
    'url' => array('action' => 'fork', $profile['id']),
);
if (!$may_edit) {
    /* The key is absent rather than empty: the strip reads it with
     * `??`, which an empty string satisfies, leaving the button with no
     * class at all. */
    $fork['class'] = 'btn btn-primary';
}
$actions[] = $fork;
if (!empty($me['Role']['perm_admin'])
    || !empty($me['Role']['perm_site_admin'])
) {
    $actions[] = array(
        'type' => 'action',
        'label' => __('Fork to my organisation'),
        'icon' => 'users',
        'url' => array('action' => 'fork', $profile['id'],
            '?' => array('for_org' => 1)),
    );
}
if (!empty($may_share)) {
    $actions[] = empty($profile['shared'])
        ? array(
            'type' => 'action',
            'label' => __('Share with everyone'),
            'icon' => 'share-nodes',
            'url' => array('action' => 'share', $profile['id']),
            'confirm' => __('Every user can read, fork and select it, and your edits reach everyone who selected it. It stops being your own profile.'),
        )
        : array(
            'type' => 'action',
            'label' => __('Stop sharing'),
            'icon' => 'share-nodes',
            'url' => array('action' => 'unshare', $profile['id']),
            'confirm' => __('Readers who selected it fall back to their next profile, and it comes back to you disabled.'),
        );
}

$this->set('headerTitle', $profile['name']);
$this->set('headerBreadcrumb', array(
    array('label' => __('Analyst Profiles'),
        'url' => array('action' => 'index')),
    $profile['name'],
));
$this->set('headerCountText', sprintf(__('rev %s'), $profile['revision']));
$this->set('headerCount', $profile['revision']);
/*
 * The subtitle is one line and a description need not be: a fork
 * carries its origin line and then everything the source said. Flatten
 * the newlines, keep the opening, and leave the rest to the sections
 * below, which are what the description was describing.
 *
 * `h()` because `headerSection.ctp` echoes this one raw — unlike
 * `headerTitle`, which it escapes and which has a separate
 * `headerTitleHtml` entry for callers with markup to pass.
 *
 * PCRE under `/u` rather than `mb_substr()`, as on the index: the
 * PRD's render harnesses run a CLI PHP without mbstring.
 */
$summary = trim(preg_replace('/\s+/u', ' ', (string)$profile['description']));
if (preg_match('/^(.{320})./u', $summary, $m)) {
    $summary = $m[1];
    $cut = strrpos($summary, ' ');
    if ($cut !== false && $cut > 160) {
        $summary = substr($summary, 0, $cut);
    }
    $summary = rtrim($summary, " ,;:") . '…';
}
$this->set('headerDescription', h($summary));
$this->set('headerActions', $actions);
$this->set('headerActionGroups', array('navigate' => array('mode' => 'none')));

echo $this->element('AnalystProfiles/workbench', array('editable' => false));
