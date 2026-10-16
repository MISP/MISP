<?php
/*
 * One request in the REST client's library: a template, a past query or a
 * bookmark. Clicking the row loads it into the request form; the tool on its
 * right is the OpenAPI description (template) or the delete (past query).
 *
 * Params:
 *   $url        string  endpoint path
 *   $method     string  HTTP method (default 'GET')
 *   $kind       string  'template' or 'query' (default 'template')
 *   $title      string  name shown above the path, optional
 *   $bookmark   bool    star the row (default false)
 *   $status     int     response code of a past query, optional
 *   $timestamp  int     when a past query ran, optional
 *   $id         int     history row id, needed for the delete
 *   $payload    array   the stored query, replayed by the client
 *   $filter     string  extra words the library filter matches on
 */
$method = strtoupper($method ?? 'GET');
$tone = ['GET' => 'success', 'POST' => 'primary', 'PUT' => 'warning', 'DELETE' => 'danger'][$method] ?? 'secondary';
$url = (string)($url ?? '');
$cut = strrpos($url, '/');
$cut = $cut === false ? 0 : $cut + 1;
$isTemplate = ($kind ?? 'template') === 'template';
$filterText = mb_strtolower(implode(' ', [$filter ?? '', $title ?? '', $method, $url]));
?>
<div class="rest-row d-flex align-items-center gap-2 rounded px-2 py-1"
     role="button" tabindex="0"
     data-rest-row="<?= $isTemplate ? 'template' : 'query' ?>"
     data-url="<?= h($url) ?>"
     data-method="<?= h($method) ?>"
     data-filter="<?= h($filterText) ?>"
     <?php if (isset($payload)): ?>data-payload="<?= h(json_encode($payload)) ?>"<?php endif; ?>>
    <span class="badge font-monospace rest-method bg-<?= $tone ?>-subtle text-<?= $tone ?>-emphasis"><?= h($method) ?></span>
    <span class="d-flex flex-column flex-grow-1 min-w-0">
        <?php if (!empty($title)): ?>
            <span class="small fw-semibold text-truncate"><?= h($title) ?></span>
        <?php endif; ?>
        <span class="font-monospace small text-body-secondary text-truncate" title="<?= h($url) ?>"><?=
            h(substr($url, 0, $cut))
        ?><strong class="text-body"><?= h(substr($url, $cut)) ?></strong></span>
        <?php if (!empty($status) || !empty($timestamp)): ?>
            <span class="d-flex align-items-center gap-2 small text-body-tertiary">
                <?php if (!empty($status)): ?>
                    <?= $this->element('Api/View/status_badge', ['code' => $status]) ?>
                <?php endif; ?>
                <?php if (!empty($timestamp)): ?>
                    <time datetime="<?= date('c', (int)$timestamp) ?>" data-rest-ago="<?= (int)$timestamp ?>"
                          title="<?= date('Y-m-d H:i:s', (int)$timestamp) ?>"><?= date('Y-m-d H:i', (int)$timestamp) ?></time>
                <?php endif; ?>
            </span>
        <?php endif; ?>
    </span>
    <?php if (!empty($bookmark)): ?>
        <i class="fas fa-star text-warning small" title="<?= __('Bookmarked') ?>"></i>
    <?php endif; ?>
    <?php if ($isTemplate): ?>
        <button type="button" class="btn btn-link btn-sm p-0 link-secondary rest-row-tool" data-rest-info
                aria-label="<?= __('About this endpoint') ?>">
            <i class="fas fa-circle-info"></i>
        </button>
    <?php elseif (!empty($id)): ?>
        <button type="button" class="btn btn-link btn-sm p-0 link-danger rest-row-tool" data-rest-delete="<?= (int)$id ?>"
                aria-label="<?= __('Delete') ?>">
            <i class="fas fa-trash-can"></i>
        </button>
    <?php endif; ?>
</div>
