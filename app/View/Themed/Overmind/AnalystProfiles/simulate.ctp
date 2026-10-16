<?php
/**
 * The bench, given the whole width.
 *
 * The same right-hand pane the editor carries, with the pane widths
 * swapped: what is being proposed on the left, every ledger row on the
 * right. It computes and it writes nothing — which is why it works on
 * a profile the analyst cannot edit, including the instance default.
 * That is how somebody decides whether they need a fork at all.
 *
 * @var array $base
 * @var array|null $in_force
 * @var array|null $detail
 * @var array $comparison
 * @var array $values
 * @var string|null $focus
 * @var int $context_builds
 * @var array $bands
 * @var bool $candidate_valid
 * @var array $errors
 * @var array $warnings
 */
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');

echo $this->element('genericElements/assetLoader', array(
    'css' => array('value-palette', 'analyst-profile'),
    'js' => array('analyst-profile'),
));

$query = $focus === null
    ? array()
    : array('value' => ValueUrlTool::encode($focus));

$this->set('headerTitle', __('Full comparison'));
$this->set('headerBreadcrumb', array(
    array('label' => __('Analyst Profiles'),
        'url' => array('action' => 'index')),
    array('label' => $base['name'],
        'url' => array('action' => 'view', $base['id'])),
    __('Full comparison'),
));
$this->set('headerCountText', $focus === null ? __('no value') : $focus);
$this->set('headerCount', count($values));
$this->set('headerDescription', __('Every ledger row, both columns, and the'
    . ' values you pinned. It computes; it writes nothing.'));
$this->set('headerActions', array(
    array(
        'type' => 'navigate',
        'label' => __('Back to the sections'),
        'icon' => 'rotate-left',
        'url' => $this->Html->url(array(
            'action' => 'edit', $base['id'], '?' => $query)),
    ),
));
$this->set('headerActionGroups', array('navigate' => array('mode' => 'none')));

$bench = array(
    'detail' => $detail,
    'focus' => $focus,
    'values' => $values,
    'comparison' => $comparison,
    'comparison_set' => $comparison_set,
    'context_builds' => $context_builds,
    /*
     * This page rebuilds the bench array from the payload's own keys
     * rather than receiving it whole, so a key added to `__simulation`
     * has to be named here too or the expanded bench quietly shows one
     * thing less than the editor's.
     */
    'dates' => isset($dates) ? $dates : null,
);
?>
<div class="ap-page">
    <div class="container-fluid">
        <?php foreach ($errors as $error): ?>
            <div class="wb-note bad mb-2"><?= h($error) ?></div>
        <?php endforeach; ?>
        <?php foreach ($warnings as $warning): ?>
            <div class="wb-note warn mb-2"><?= h($warning) ?></div>
        <?php endforeach; ?>

        <div class="wb wb-flip">
            <div class="wb-panehead wb-panehead-left">
                <span><?= h(__('What you are proposing')) ?></span>
                <em><?= $detail === null
                    ? h(__('no value chosen'))
                    : h(sprintf(__n('%s difference', '%s differences',
                        count($detail['moved'])), count($detail['moved']))) ?></em>
            </div>
            <div class="wb-panehead wb-panehead-right">
                <span><?= h(__('The value under assessment')) ?></span>
                <em><?= h(__('both columns sum exactly')) ?></em>
            </div>

            <div class="wb-body">
                <table class="wb-tbl mb-3">
                    <tbody>
                        <tr>
                            <td style="width:6.5rem">
                                <span class="pill t-plain"><?= h(__('in force')) ?></span>
                            </td>
                            <td>
                                <?php if ($in_force === null): ?>
                                    <div class="fw-semibold"><?= h(__('Nothing')) ?></div>
                                    <div class="wb-sub"><?= h(__('No profile'
                                        . ' applies to you, so the left column'
                                        . ' is what no scoring at all looks'
                                        . ' like.')) ?></div>
                                <?php else: ?>
                                    <div class="fw-semibold"><?= h($in_force['name']) ?></div>
                                    <div class="wb-sub num"><?= h(sprintf(
                                        __('v %1$s · rev %2$s · the column your'
                                            . ' pages are scored by today'),
                                        $in_force['version'],
                                        $in_force['revision']
                                    )) ?></div>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <tr>
                            <td><span class="pill t-force"><?= h(__('candidate')) ?></span></td>
                            <td>
                                <div class="fw-semibold"><?= h($base['name']) ?></div>
                                <div class="wb-sub num"><?= h(sprintf(
                                    __('v %1$s · rev %2$s · scored in memory,'
                                        . ' never written'),
                                    $base['version'],
                                    $base['revision']
                                )) ?></div>
                            </td>
                        </tr>
                    </tbody>
                </table>

                <?php if (!$candidate_valid): ?>
                    <div class="wb-note bad">
                        <b><?= h(__('This candidate could not be saved.')) ?></b>
                        <?= h(__('It is simulated anyway — seeing what a'
                            . ' document would do is how you find out that'
                            . ' it is wrong.')) ?>
                    </div>
                <?php endif; ?>

                <div class="wb-note">
                    <b class="num"><?= h($context_builds) ?></b>
                    <?= h(__n('context build.', 'context builds.',
                        $context_builds)) ?>
                    <?= $context_builds <= count($values)
                        ? h(__('The two profiles have the same exclusions, so'
                            . ' both columns are scored over the same rows and'
                            . ' only the weighting differs.'))
                        : h(__('The two profiles exclude different rows, so'
                            . ' each column is scored over a different set of'
                            . ' them — the row counts themselves differ.')) ?>
                </div>

                <a class="btn btn-sm btn-outline-secondary w-100 mt-3"
                   href="<?= h($this->Html->url(array(
                       'action' => 'edit', $base['id'], '?' => $query))) ?>">
                    <?= h(__('Back to the sections')) ?>
                </a>
                <p class="wb-sub mt-2 mb-0">
                    <?= h(__('The editor is where you change a number; this'
                        . ' page is the same bench widened, for reading every'
                        . ' row rather than the few that moved.')) ?>
                </p>
            </div>

            <aside class="wb-bench">
                <?= $this->element('AnalystProfiles/bench', array(
                    'bench' => $bench,
                    'bands' => $bands,
                    'full' => true,
                    'profileId' => $base['id'],
                )) ?>
            </aside>
        </div>
    </div>
</div>
