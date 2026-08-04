<?php
App::uses('CakeNumber', 'Utility');

$this->set('headerTitle', __('Access logs'));
$this->set('headerDescription', __('HTTP requests served by this instance, with timing and resource usage.'));
// Standard paginator → exact total; abbreviate it (no "+") in the header.
$this->set('headerCountApprox', false);

$methodOptions = ['' => __('Any method')];
foreach (['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'PATCH'] as $m) {
    $methodOptions[$m] = $m;
}

$filterFields = [
    ['name' => 'url', 'label' => __('URL contains'), 'type' => 'text', 'placeholder' => __('Search URLs…'), 'col' => 6],
    ['name' => 'request_method', 'label' => __('HTTP method'), 'type' => 'select', 'options' => $methodOptions, 'col' => 3],
    ['name' => 'response_code', 'label' => __('Response code'), 'type' => 'number', 'placeholder' => __('e.g. 200'), 'col' => 3],
    ['name' => 'user', 'label' => __('User'), 'type' => 'text', 'placeholder' => __('ID or e-mail'), 'col' => 3],
    ['name' => 'org', 'label' => __('Organisation'), 'type' => 'text', 'placeholder' => __('ID, UUID or name'), 'col' => 3],
    ['name' => 'ip', 'label' => __('IP'), 'type' => 'text', 'col' => 3],
    ['name' => 'controller', 'label' => __('Controller'), 'type' => 'text', 'col' => 3],
    ['name' => 'action', 'label' => __('Action'), 'type' => 'text', 'col' => 3],
    ['name' => 'request_id', 'label' => __('Request ID'), 'type' => 'text', 'col' => 3],
    ['name' => 'authkey_id', 'label' => __('Auth key ID'), 'type' => 'number', 'col' => 3],
    ['name' => 'user_agent', 'label' => __('User agent'), 'type' => 'text', 'col' => 6],
    ['name' => 'memory_usage', 'label' => __('Memory usage'), 'type' => 'number', 'step' => '0.01', 'placeholder' => __('≥ MB'), 'col' => 3],
    ['name' => 'duration', 'label' => __('Duration'), 'type' => 'number', 'placeholder' => __('≥ ms'), 'col' => 3],
    ['name' => 'query_count', 'label' => __('Query count'), 'type' => 'number', 'placeholder' => __('≥ n'), 'col' => 3],
    ['name' => 'created', 'label' => __('Created after'), 'type' => 'date', 'col' => 3, 'help' => __('Date or relative delta (e.g. 7d)')],
];

$methodClass = function ($method) {
    switch ($method) {
        case 'POST':   return 'text-bg-primary';
        case 'PUT':
        case 'PATCH':  return 'text-bg-warning';
        case 'DELETE': return 'text-bg-danger';
        case 'GET':
        case 'HEAD':   return 'text-bg-secondary';
        default:       return 'text-bg-light border';
    }
};
$codeClass = function ($code) {
    $code = (int)$code;
    if ($code >= 500) { return 'text-bg-danger'; }
    if ($code >= 400) { return 'text-bg-warning'; }
    if ($code >= 300) { return 'text-bg-info'; }
    if ($code >= 200) { return 'text-bg-success'; }
    return 'text-bg-secondary';
};
$P = $this->Paginator;
?>

<div class="container-fluid">

    <?= $this->element('Logs/filter_card', [
        'item_url'      => '/admin/access_logs',
        'search'        => ['placeholder' => __('Filter this page…')],
        'fields'        => $filterFields,
        'pager_element' => 'Logs/pager_prevnext',
    ]) ?>

    <div class="card shadow-sm mb-4">
        <div class="card-body p-0">
            <div class="table-responsive table-scroll">
                <table class="table table-hover align-middle mb-0">
                    <thead class="checkbox-index">
                        <tr>
                            <th><?= $P->sort('created', __('Created')) ?></th>
                            <th><?= $P->sort('user_id', __('User')) ?></th>
                            <th><?= $P->sort('ip', __('IP')) ?></th>
                            <th><?= $P->sort('org_id', __('Org')) ?></th>
                            <th><?= $P->sort('request_method', __('Method')) ?></th>
                            <th><?= $P->sort('url', __('URL')) ?></th>
                            <th title="<?= __('HTTP response code') ?>"><?= $P->sort('response_code', __('Code')) ?></th>
                            <th class="text-end" title="<?= __('Memory used while responding') ?>"><?= $P->sort('memory_usage', __('Memory')) ?></th>
                            <th class="text-end" title="<?= __('Time used while responding') ?>"><?= $P->sort('duration', __('Duration')) ?></th>
                            <th class="text-end" title="<?= __('SQL query count') ?>"><?= $P->sort('query_count', __('Queries')) ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($list)): ?>
                            <tr>
                                <td colspan="10" class="text-center text-muted py-5">
                                    <span class="d-flex flex-column align-items-center">
                                        <i class="fas fa-inbox fa-2x opacity-25 mb-2"></i>
                                        <?= __('No access log entries to display.') ?>
                                    </span>
                                </td>
                            </tr>
                        <?php endif; ?>
                        <?php foreach (($list ?? []) as $item): $a = $item['AccessLog'];
                            $rowSearch = strtolower(trim(implode(' ', [
                                $a['url'] ?? '', $a['ip'] ?? '', $a['request_method'] ?? '',
                                (string)($a['response_code'] ?? ''), $item['User']['email'] ?? '',
                                $item['Organisation']['name'] ?? '', $a['controller'] ?? '',
                                $a['action'] ?? '', $a['request_id'] ?? '', $a['user_agent'] ?? '',
                            ]))); ?>
                            <tr data-search="<?= h($rowSearch) ?>">
                                <td class="text-nowrap small"><?= $this->Time->time($a['created']) ?></td>

                                <td class="small">
                                    <?php if (isset($item['User']['email'])): ?>
                                        <a href="<?= $baseurl ?>/admin/users/view/<?= h($item['User']['id']) ?>"
                                           class="text-decoration-none"><?= h($item['User']['email']) ?></a>
                                    <?php elseif (!empty($a['user_id'])): ?>
                                        <em class="text-muted"><?= __('Deleted user #%s', h($a['user_id'])) ?></em>
                                    <?php else: ?>
                                        <span class="text-muted">&mdash;</span>
                                    <?php endif; ?>
                                    <?php if (!empty($a['authkey_id'])): ?>
                                        <i class="fas fa-cogs text-muted ms-1"
                                           title="<?= __('Request through API by auth key #%s', h($a['authkey_id'])) ?>"></i>
                                    <?php endif; ?>
                                </td>

                                <td class="text-nowrap small font-monospace"><?= h($a['ip']) ?></td>

                                <td class="small">
                                    <?php if (isset($item['Organisation']) && !empty($item['Organisation']['id'])): ?>
                                        <?= $this->OrgImg->getOrgLogo($item, 24) ?>
                                    <?php elseif (!empty($a['org_id']) && (int)$a['org_id'] !== 0): ?>
                                        <em class="text-muted"><?= __('Deleted org #%s', h($a['org_id'])) ?></em>
                                    <?php else: ?>
                                        <span class="text-muted">&mdash;</span>
                                    <?php endif; ?>
                                </td>

                                <td class="text-nowrap">
                                    <span class="badge <?= $methodClass($a['request_method']) ?>"
                                          title="<?= __("User agent: %s\nRequest ID: %s", h($a['user_agent']), h($a['request_id'])) ?>"><?= h($a['request_method']) ?></span>
                                    <?php if (in_array($a['request_method'], ['POST', 'PUT', 'PATCH'], true)): ?>
                                        <button type="button" class="btn btn-link btn-sm p-0 ms-1 text-decoration-none"
                                                title="<?= __('Show HTTP request') ?>"
                                                onclick="openModal('<?= $baseurl ?>/admin/access_logs/request/<?= h($a['id']) ?>')">
                                            <i class="far fa-file-alt"></i>
                                        </button>
                                    <?php endif; ?>
                                </td>

                                <td class="small text-break" style="max-width:360px;"
                                    title="<?= __('Controller: %s, action: %s', h($a['controller']), h($a['action'])) ?>"><?= h($a['url']) ?></td>

                                <td><span class="badge <?= $codeClass($a['response_code']) ?>"><?= h($a['response_code']) ?></span></td>

                                <td class="text-end text-nowrap small"><?= h(CakeNumber::toReadableSize($a['memory_usage'])) ?></td>

                                <td class="text-end text-nowrap small"><?= h($a['duration']) ?> ms</td>

                                <td class="text-end text-nowrap small">
                                    <?= h($a['query_count']) ?>
                                    <?php if (!empty($a['has_query_log'])): ?>
                                        <button type="button" class="btn btn-link btn-sm p-0 ms-1 text-decoration-none"
                                                title="<?= __('Show SQL queries') ?>"
                                                onclick="openModal('<?= $baseurl ?>/admin/access_logs/queryLog/<?= h($a['id']) ?>')">
                                            <i class="fas fa-database"></i>
                                        </button>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="card shadow-sm mb-4">
        <div class="card-body">
            <?= $this->element('genericElementsBS5/IndexTable/pagination') ?>
        </div>
    </div>

</div>
