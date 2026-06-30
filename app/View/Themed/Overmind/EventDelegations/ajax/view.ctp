<?php
/**
 * Accept / decline a delegation request.
 *
 */
$delegationId = h($delegation['EventDelegation']['id']);

$target = $me['org_id'] == $delegation['Org']['id']
    ? __('your organisation')
    : $delegation['Org']['name'];
$requester = $me['org_id'] == $delegation['RequesterOrg']['id']
    ? __('Your organisation')
    : $delegation['RequesterOrg']['name'];

$canAccept = $isSiteAdmin || $me['org_id'] == $delegation['Org']['id'];
?>
<div class="d-flex justify-content-center">
    <div class="card shadow-sm d-inline-block">
        <div class="card-header">
            <h4 class="card-title mb-2 mt-2">
                <?= __('Event Delegation') ?>
            </h4>
        </div>

        <div class="card-body" style="padding:2rem">
            <h6 class="fw-bold mb-1"><?= __('Request details') ?></h6>
            <p class="mb-3">
                <?= __(
                    '%s is requesting %s to take over this event.',
                    '<span class="fw-bold text-danger">' . h($requester) . '</span>',
                    '<span class="fw-bold text-danger">' . h($target) . '</span>'
                ) ?>
                <?php if ($delegation['EventDelegation']['distribution'] != -1): ?>
                    <br>
                    <?php if ($delegation['EventDelegation']['distribution'] < 4): ?>
                        <?= __('The desired distribution level is') ?>
                        <span class="fw-bold text-danger"><?= h($delegation['requested_distribution_level']) ?></span>
                    <?php else: ?>
                        <?= __('The desired sharing group to distribute the event to is') ?>:
                        <span class="fw-bold text-danger"><?= h($delegation['SharingGroup']['name']) ?></span>.
                    <?php endif; ?>
                <?php endif; ?>
            </p>

            <h6 class="fw-bold mb-1"><?= __('Message from requester') ?></h6>
            <p class="mb-4 text-muted">
                <?= nl2br(h($delegation['EventDelegation']['message'])) ?>
            </p>

            <div class="d-flex justify-content-between align-items-center gap-2">
                <div class="d-flex gap-2">
                    <?php if ($canAccept): ?>
                        <?php
                            echo $this->Form->create('EventDelegation', [
                                'id' => 'AcceptDelegationForm',
                                'url' => $baseurl . '/event_delegations/acceptDelegation/' . $delegationId,
                                'class' => 'm-0',
                            ]);
                        ?>
                        <button
                            type="submit"
                            class="btn btn-primary"
                            title="<?= __('Accept delegation request') ?>"
                            aria-label="<?= __('Accept delegation request') ?>">
                            <i class="fas fa-check me-1"></i><?= __('Accept') ?>
                        </button>
                        <?= $this->Form->end() ?>
                    <?php endif; ?>

                    <?php
                        echo $this->Form->create('EventDelegation', [
                            'id' => 'DeclineDelegationForm',
                            'url' => $baseurl . '/event_delegations/deleteDelegation/' . $delegationId,
                            'class' => 'm-0',
                        ]);
                    ?>
                    <button
                        type="submit"
                        class="btn btn-outline-danger"
                        title="<?= __('Decline and remove delegation request') ?>"
                        aria-label="<?= __('Decline and remove delegation request') ?>">
                        <i class="fas fa-xmark me-1"></i><?= __('Discard') ?>
                    </button>
                    <?= $this->Form->end() ?>
                </div>

                <button
                    type="button"
                    class="btn btn-outline-secondary"
                    title="<?= __('Cancel') ?>"
                    aria-label="<?= __('Cancel') ?>"
                    onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();">
                    <?= __('Cancel') ?>
                </button>
            </div>
        </div>
    </div>
</div>
