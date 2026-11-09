<?php
/**
 * What the view keeps behind its About button, as the content of
 * #mainModal. The header says where the profile stands for this reader;
 * below come its whole description, which the page header cuts short,
 * and the facts. Where the copy came from goes in the footer.
 *
 * @var array $profile
 * @var array|null $standing This profile's row of the index board
 */
// The fact the owner alone does not give: MISP's version, or who it is shared with.
$origin = null;
if (!empty($profile['default'])) {
    $origin = array(__('Shipped version'), 'v' . $profile['version']
        . ($profile['edited_here'] ? ' · ' . __('edited here') : ''));
} elseif (!empty($profile['shared'])) {
    $origin = array(__('Sharing'), __('Everyone on this instance'));
}
$description = trim((string)$profile['description']);
// The dated notes `AnalystProfile::forkDescription()` puts ahead of the text, one per fork.
$forkNote = '/^' . str_replace(array('%1\$s', '%2\$s'), array('.+?', '\d{4}-\d{2}-\d{2}'),
    preg_quote(__('Forked from “%1$s” on %2$s.'), '/')) . '$/u';
$paragraphs = preg_split('/\R{2,}/u', $description);
$forks = array();
while (!empty($paragraphs) && preg_match($forkNote, trim($paragraphs[0]))) {
    $forks[] = trim(array_shift($paragraphs));
}
$description = trim(implode("\n\n", $paragraphs));

echo $this->element('genericElementsBS5/Forms/modal_header', array(
    'eyebrow' => h(__('About this profile')),
    'title' => h($profile['name']),
    'titleBadge' => $standing === null ? '' : $this->element(
        'AnalystProfiles/standing', array('profile' => $standing, 'part' => 'pill')),
    'description' => $standing === null ? '' : $this->element(
        'AnalystProfiles/standing', array('profile' => $standing, 'part' => 'line')),
    'escape' => false,
    'titleIcon' => 'fas fa-circle-info',
    'icon' => 'fas fa-sliders',
    'accent' => 'primary',
));
?>
<div class="px-4 py-3 ap-about-modal">
    <?php if ($description !== ''): ?>
        <p class="ap-about-desc"><?= h($description) ?></p>
    <?php endif; ?>

    <p class="ap-about-h"><?= h(__('The profile')) ?></p>
    <dl class="ap-about-facts">
        <?php if ($standing !== null): ?>
            <div><dt><?= h(__('Owner')) ?></dt><dd><?= h($standing['owner']) ?></dd></div>
        <?php endif; ?>
        <?php if ($origin !== null): ?>
            <div><dt><?= h($origin[0]) ?></dt><dd><?= h($origin[1]) ?></dd></div>
        <?php endif; ?>
        <div>
            <dt><?= h(__('Revision')) ?></dt>
            <dd>
                <?= h($profile['revision']) ?>
                <?php if (!empty($profile['modified'])): ?>
                    <?php $saved = is_numeric($profile['modified'])
                        ? (int)$profile['modified'] : strtotime($profile['modified']); ?>
                    <span class="ap-about-sub">· <?= h(sprintf(__('saved %s'),
                        date('Y-m-d H:i', $saved))) ?></span>
                <?php endif; ?>
            </dd>
        </div>
        <?php if ($standing !== null): ?>
            <div><dt><?= h(__('Signals on')) ?></dt><dd><?= h(sprintf(__('%s of %s'),
                $standing['signals']['enabled'], $standing['signals']['configured'])) ?></dd></div>
        <?php endif; ?>
    </dl>
</div>
<?= $this->element('genericElementsBS5/Forms/modal_footer', array(
    'accent' => 'primary',
    'bleed' => true,
    'align' => empty($forks) ? 'end' : 'between',
    'metaHtml' => empty($forks) ? null : '<span class="ap-about-fork">'
        . '<i class="fas fa-code-branch me-1" aria-hidden="true"></i>'
        . h(implode(' ', $forks)) . '</span>',
    'cancel' => array('label' => __('Close'), 'icon' => 'fas fa-xmark'),
    'submit' => false,
)) ?>
