<?php
/**
 * Whom the profile scores: its standing for this reader, then what each
 * scope answers with, in the order MISP asks them.
 *
 * @var array $profile
 * @var array|null $standing This profile's row of the index board
 * @var array|null $scope_answers
 */
if (empty($scope_answers)) {
    return;
}
$labels = array(
    'user' => __('You'),
    'org' => __('Your organisation'),
    'instance' => __('This instance'),
);
$reasons = array(
    'missing' => __('the profile it named is gone'),
    'disabled' => __('the profile it named is switched off'),
    'unreadable' => __('it may not use the profile it named'),
);
$step = 1;
?>
<section class="card ap-rcard" aria-label="<?= h(__('Who it scores')) ?>">
    <header class="ap-rcard-h">
        <span class="ap-vcard-ico" aria-hidden="true"><i class="fas fa-users"></i></span>
        <h2 class="ap-rcard-t"><?= h(__('Who it scores')) ?></h2>
    </header>
    <div class="ap-rcard-b">
        <?php if ($standing !== null): ?>
            <div class="ap-scores-standing"><?= $this->element(
                'AnalystProfiles/standing', array('profile' => $standing)) ?></div>
        <?php endif; ?>
        <ol class="ap-scores" aria-label="<?= h(__('Resolution order')) ?>">
            <?php foreach ($labels as $scope => $label): ?>
                <?php
                $answer = $scope_answers['answers'][$scope];
                $here = $answer['profile'] !== null
                    && (int)$answer['profile']['id'] === (int)$profile['id'];
                $won = $scope_answers['won_by'] === $scope;
                ?>
                <li class="ap-score<?= $here ? ' is-here' : ''
                    ?><?= $won ? ' is-win' : '' ?>">
                    <span class="ap-hop-n"><?= h($step++) ?></span>
                    <span class="ap-score-l"><?= h($label) ?></span>
                    <?php if ($here): ?>
                        <span class="ap-score-a is-here"><?= h(
                            $scope === 'instance' ? __('runs it') : __('uses it')) ?></span>
                    <?php elseif ($answer['profile'] !== null): ?>
                        <a class="ap-score-a" href="<?= h($this->Html->url(array(
                            'action' => 'view', $answer['profile']['id']))) ?>"><?=
                            h($answer['profile']['name']) ?></a>
                    <?php elseif ($answer['reason'] !== null): ?>
                        <span class="ap-score-a is-warn"><?= h(
                            isset($reasons[$answer['reason']])
                                ? $reasons[$answer['reason']]
                                : $answer['reason']) ?></span>
                    <?php else: ?>
                        <span class="ap-score-a is-none"><?= h(__('no answer')) ?></span>
                    <?php endif; ?>
                </li>
            <?php endforeach; ?>
        </ol>
        <p class="ap-score-note"><?= h(__('MISP asks these three in order;'
            . ' the first answer scores your pages.')) ?></p>
    </div>
</section>
