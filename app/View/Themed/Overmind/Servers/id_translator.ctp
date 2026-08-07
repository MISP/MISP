<div class="container-fluid py-4">
    <div class="row mb-4">
        <div class="col-12">
            <h2 class="fw-bold"><i class="fas fa-exchange-alt text-primary me-2"></i><?= __('Event ID Translator') ?></h2>
            <p class="text-muted"><?= __('Convert local IDs to remote sync server IDs in a few clicks.') ?></p>
        </div>
    </div>

    <div class="card border-0 shadow-sm rounded-4 mb-4">
        <div class="card-body p-4">
            <?= $this->Form->create('Event', ['class' => 'row g-3 align-items-end']); ?>

                <div class="col-md-4">
                    <label class="form-label fw-bold text-secondary small text-uppercase"><?= __("Event ID or UUID") ?></label>
                    <div class="input-group">
                        <span class="input-group-text bg-white border-end-0"><i class="fas fa-fingerprint text-muted"></i></span>
                        <?= $this->Form->control('uuid', [
                            'label' => false,
                            'div' => false,
                            'class' => 'form-control border-start-0 ps-0 bg-light',
                            'placeholder' => '1234...'
                        ]); ?>
                    </div>
                </div>

                <div class="col-md-3">
                    <label class="form-label fw-bold text-secondary small text-uppercase ms-1"><?= __("Scope") ?></label>
                    <?= $this->Form->select('local', 
                        ['local' => __('Local Event'), 'remote' => __('Remote Event')], 
                        [
                            'empty' => false,
                            'class' => 'form-select bg-light fw-medium',
                            'id' => 'EventLocal'
                        ]
                    ); ?>
                </div>

                <div id="serverSelectWrapper" class="col-md-3 d-none">
                    <label class="form-label fw-bold text-secondary small text-uppercase ms-1"><?= __("Reference Server") ?></label>
                    <?= $this->Form->select('Server.id', 
                        $servers, 
                        [
                            'empty' => __('Select a server...'),
                            'class' => 'form-select bg-light fw-medium',
                            'id' => 'ServerId'
                        ]
                    ); ?>
                </div>

                <div class="col-md-2">
                    <button type="submit" class="btn btn-primary w-100 fw-bold py-2 shadow-sm">
                        <i class="fas fa-search me-2"></i><?= __('Translate') ?>
                    </button>
                </div>

            <?= $this->Form->end(); ?>
        </div>
    </div>

    <div class="view-results">
        <?= $this->Flash->render() ?>

        <?php if (isset($remote_events) && isset($local_event)): ?>
            <div class="row">
                <div class="col-lg-4">
                    <div class="card border-0 shadow-sm rounded-4 h-100 border-start border-4 border-primary">
                        <div class="card-body">
                            <h6 class="text-uppercase fw-bold text-primary mb-3"><?= __('Local Source') ?></h6>
                            <div class="mb-3">
                                <label class="text-muted small d-block"><?= __('Event Info') ?></label>
                                <span class="fw-semibold"><?= h($local_event['Event']['info']) ?></span>
                            </div>
                            <div class="bg-light p-3 rounded-3">
                                <div class="d-flex justify-content-between align-items-end">
                                    <div class="">
                                        <div class="text-muted small text-uppercase fw-bold mb-1">
                                            ID
                                        </div>

                                        <div class="d-flex align-items-center gap-2">
                                            <span class="badge bg-white text-dark border fw-bold">
                                                <?= $local_event['Event']['id'] ?>
                                            </span>
                                        </div>
                                    </div>

                                    <div class="">
                                        <div class="text-muted small text-uppercase fw-bold mb-1">
                                            UUID
                                        </div>

                                        <div class="d-flex align-items-center gap-2">

                                            <div class="bg-light rounded" id="uuid-value">
                                                <span class="badge bg-white text-dark border fw-bold">
                                                    <?= $local_event['Event']['uuid'] ?>
                                                </span>
                                            </div>

                                            <a
                                                class="text-muted bg-light"
                                                style="cursor:pointer"
                                                onclick="copyToClipboard(this, '<?= h(h($local_event['Event']['uuid'] ?? '')) ?>')"
                                                data-bs-toggle="tooltip"
                                                title="<?= __('Copy UUID') ?>"
                                                aria-label="<?= __('Copy UUID') ?>">
                                                <i class="fas fa-copy"></i>
                                            </a>

                                        </div>
                                    </div>

                                    <div class="text-end">
                                        <a href="<?= $baseurl ?>/events/view2/<?= $local_event['Event']['id'] ?>"
                                        class="btn btn-light btn-sm rounded-pill"
                                        target="_blank">
                                            <i class="fas fa-eye text-primary"></i>
                                        </a>
                                    </div>

                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-lg-8">
                    <div class="card border-0 shadow-sm rounded-4 h-100">
                        <div class="card-body">
                            <h6 class="text-uppercase fw-bold text-secondary mb-3"><?= __('Synchronized Servers') ?></h6>
                            <div class="table-responsive">
                                <table class="table table-borderless align-middle">
                                    <thead class="table-light">
                                        <tr class="small text-uppercase text-muted">
                                            <th><?= __('Server Instance') ?></th>
                                            <th><?= __('Status / Remote ID') ?></th>
                                            <th class="text-end"><?= __('Actions') ?></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($remote_events as $remote_event): ?>
                                            <tr class="border-bottom">
                                                <td class="fw-bold"><?= h($remote_event['server_name']) ?></td>
                                                <td>
                                                    <?php if ($remote_event['remote_id']): ?>
                                                        <span class="badge rounded-pill bg-success-subtle text-success border border-success-subtle px-3 py-2">
                                                            <i class="fas fa-check-circle me-1"></i> ID: <?= $remote_event['remote_id'] ?>
                                                        </span>
                                                    <?php elseif ($remote_event['exception']): ?>
                                                        <span class="text-danger small"><i class="fas fa-times-circle me-1"></i> <?= __('Unreachable') ?></span>
                                                    <?php else: ?>
                                                        <span class="text-muted small fst-italic"><?= __('Not Found') ?></span>
                                                    <?php endif; ?>
                                                </td>
                                                <td class="text-end">
                                                    <?php if ($remote_event['remote_id']): ?>
                                                        <a href="<?= h($remote_event['url']) ?>" class="btn btn-outline-secondary btn-sm rounded-pill" target="_blank">
                                                            <i class="fas fa-link"></i>
                                                        </a>
                                                        <?php if ($isSiteAdmin): ?>
                                                            <a href="<?= $baseurl ?>/servers/previewEvent/<?= $remote_event['server_id'] ?>/<?= $remote_event['remote_id'] ?>" class="btn btn-light btn-sm rounded-pill">
                                                                <i class="fas fa-glasses"></i>
                                                            </a>
                                                        <?php endif; ?>
                                                    <?php endif; ?>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </div>
</div>


<script type="text/javascript">
document.addEventListener('DOMContentLoaded', () => {
    const selectLocal = document.getElementById('EventLocal');
    const serverWrapper = document.getElementById('serverSelectWrapper');

    const updateVisibility = () => {
        if (selectLocal.value === 'remote') {
            serverWrapper.classList.remove('d-none');
            serverWrapper.style.opacity = 0;
            setTimeout(() => {
                serverWrapper.style.transition = "opacity 0.3s ease";
                serverWrapper.style.opacity = 1;
            }, 10);
        } else {
            serverWrapper.classList.add('d-none');
        }
    };

    selectLocal.addEventListener('change', updateVisibility);
    updateVisibility(); // Init au chargement
});
</script>