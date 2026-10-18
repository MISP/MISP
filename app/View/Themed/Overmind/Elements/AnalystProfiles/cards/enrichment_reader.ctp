<?php
/**
 * The enrichment card for a reader who is not a site admin: which of the
 * modules their own profile asks for can run for them, and what their
 * organisation's stored answers came to.
 *
 * @var array $card From IndexCardsTool::reader()
 * @var array $answers From ValueEnrichmentRun::errorShareFor()
 */
$groups = array(
    IndexCardsTool::MODULE_OFF => __('Switched off here'),
    IndexCardsTool::MODULE_SETTINGS => __('Not set up here'),
    IndexCardsTool::MODULE_MISSING => __('Not on this instance'),
    IndexCardsTool::MODULE_RESTRICTED => __('Reserved for another organisation'),
);
$blocked = $card['asked'] - $card['ready'];
$status = null;
if ($card['service'] === IndexCardsTool::SERVICE_ON && $card['asked'] > 0
    && $card['can_run']
) {
    $status = $blocked > 0
        ? array('text' => __n('%s cannot run', '%s cannot run', $blocked, $blocked),
            'tone' => 't-over')
        : array('text' => __('all ready'), 'tone' => 't-plain');
}
?>
<section class="ap-card ap-card-enrich" data-ap-card="enrichment">
    <?= $this->element('AnalystProfiles/cards/head', array(
        'icon' => 'puzzle-piece',
        'title' => __('Your enrichment'),
        'status' => $status,
    )) ?>

    <?php if ($card['profile'] === null): ?>
        <p class="ap-card-line"><?= h(__('No profile is in force for you, so'
            . ' none asks for a module.')) ?></p>
    <?php elseif ($card['service'] === IndexCardsTool::SERVICE_OFF): ?>
        <p class="ap-card-line"><?= h(__('Enrichment is switched off on this'
            . ' instance, so no module runs.')) ?></p>
    <?php elseif ($card['service'] === IndexCardsTool::SERVICE_UNREACHABLE): ?>
        <p class="ap-card-line"><?= h(__('The modules service is not'
            . ' answering, so which modules can run cannot be checked.')) ?></p>
    <?php elseif ($card['asked'] === 0): ?>
        <p class="ap-card-line"><?= h(__('%s asks for no enrichment module.',
            $card['profile'])) ?></p>
    <?php elseif (!$card['can_run']): ?>
        <p class="ap-card-line"><?= h(__n(
            '%s asks for %s module, but your role cannot run enrichment modules.',
            '%s asks for %s modules, but your role cannot run enrichment modules.',
            $card['asked'], $card['profile'], $card['asked'])) ?></p>
    <?php else: ?>
        <div class="ap-card-fig">
            <span class="ap-card-n"><?= h($card['ready']) ?></span>
            <span class="ap-card-of"><?= __n(
                'of the %s module %s asks for can run for you',
                'of the %s modules %s asks for can run for you',
                $card['asked'], h($card['asked']),
                '<b>' . h($card['profile']) . '</b>') ?></span>
        </div>
        <?php if (!empty($card['groups'])): ?>
            <dl class="ap-reasons">
                <?php foreach ($card['groups'] as $key => $names): ?>
                    <div>
                        <dt><?= h($groups[$key]) ?></dt>
                        <dd><?php foreach ($names as $i => $name): ?><?= $i > 0 ? ', ' : ''
                            ?><span class="ap-item-name"><?= h($name) ?></span><?php endforeach; ?></dd>
                    </div>
                <?php endforeach; ?>
            </dl>
        <?php endif; ?>
        <?php if ($card['auto_held'] !== null): ?>
            <p class="ap-card-line">
                <?= h(__n(
                    '%s is marked to run without a press, which this instance %s.',
                    '%s are marked to run without a press, which this instance %s.',
                    count($card['auto']), implode(', ', $card['auto']),
                    $card['auto_held'] === ValueEnrichmentTool::GATE_SITE_ADMIN
                        ? __('allows for site admins only')
                        : __('holds back'))) ?>
            </p>
        <?php endif; ?>
    <?php endif; ?>

    <footer class="ap-card-foot">
        <?php if ($answers['total'] === 0): ?>
            <?= h(__('Your organisation holds no stored answers yet.')) ?>
        <?php else: ?>
            <?= h(__n('Your organisation holds %s stored answer',
                'Your organisation holds %s stored answers',
                $answers['total'], number_format($answers['total']))) ?>
            <?php if ($answers['errors'] > 0): ?>
                &middot;
                <?php if ($answers['read'] >= $answers['total']): ?>
                    <?= h(__n('%s came back with an error',
                        '%s came back with an error',
                        $answers['errors'], number_format($answers['errors']))) ?>
                <?php else: ?>
                    <?= h(__('about %s%% came back with an error',
                        round(100 * $answers['errors'] / max(1, $answers['read'])))) ?>
                <?php endif; ?>
            <?php endif; ?>
        <?php endif; ?>
        <?php if (!empty($card['groups'])): ?>
            <br><?= h(__('A site admin can change what this instance offers.')) ?>
        <?php endif; ?>
    </footer>
</section>
