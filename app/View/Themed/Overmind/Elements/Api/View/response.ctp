<?php
App::uses('CakeNumber', 'Utility');

$hasResponse = isset($data) && is_array($data) && isset($data['code']);
if ($hasResponse) {
    $rawBody = (string)($data['data'] ?? '');
    $responseHeaders = $data['headers'] ?? [];
    $showResult = !empty($this->request->data['Server']['show_result']);

    $responseBody = $rawBody;
    $decodedBody = json_decode($rawBody);
    $isJson = $rawBody !== '' && json_last_error() === JSON_ERROR_NONE;
    if ($isJson) {
        $responseBody = json_encode($decodedBody, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    $responseCookies = [];
    foreach ($responseHeaders as $key => $value) {
        if (strtolower($key) === 'set-cookie') {
            $responseCookies = is_array($value) ? $value : [$value];
        }
    }

    $snippets = array_filter([
        'curl' => ['label' => 'cURL', 'icon' => 'fas fa-terminal', 'code' => $curl ?? ''],
        'pymisp' => ['label' => 'PyMISP', 'icon' => 'fab fa-python', 'code' => $python ?? ''],
    ], function ($snippet) {
        return $snippet['code'] !== '';
    });
}

$codeBlock = function ($id, $text, $json = false) {
    return sprintf(
        '<div class="d-flex overflow-auto bg-body-tertiary rounded-bottom rest-code" data-rest-code>'
        . '<pre class="m-0 py-3 ps-3 pe-2 text-end text-body-tertiary border-end bg-body-secondary user-select-none position-sticky start-0" aria-hidden="true" data-rest-lines></pre>'
        . '<pre class="m-0 p-3 flex-grow-1 rest-code-text" id="%s"%s>%s</pre>'
        . '</div>',
        h($id),
        $json ? ' data-rest-json' : '',
        h($text)
    );
};
?>
<section class="card shadow-sm" id="rest-response" aria-labelledby="rest-response-title"<?= $hasResponse ? ' data-rest-response' : '' ?>>
    <div class="card-header bg-body d-flex flex-wrap align-items-center gap-3 py-2">
        <h2 class="h6 fw-bold mb-0" id="rest-response-title"><?= __('Response') ?></h2>
        <?php if ($hasResponse): ?>
            <?= $this->element('Api/View/status_badge', ['code' => $data['code'], 'chip' => true]) ?>
            <?php if (!empty($data['duration'])): ?>
                <span class="small text-body-secondary"><i class="far fa-clock me-1"></i><?= h($data['duration']) ?></span>
            <?php endif; ?>
            <?php if ($showResult): ?>
                <span class="small text-body-secondary"><i class="fas fa-weight-hanging me-1"></i><?= h(CakeNumber::toReadableSize(strlen($rawBody))) ?></span>
            <?php endif; ?>
            <div class="ms-auto d-flex gap-1">
                <?php if ($showResult): ?>
                    <button type="button" class="btn btn-sm btn-outline-secondary border-0" id="rest-response-wrap" aria-pressed="false"
                            title="<?= __('Wrap long lines') ?>" aria-label="<?= __('Wrap long lines') ?>">
                        <i class="fas fa-paragraph"></i>
                    </button>
                <?php endif; ?>
                <button type="button" class="btn btn-sm btn-outline-secondary border-0" data-rest-copy="#response-body-code"
                        data-rest-copied="<?= __('Response copied') ?>"
                        title="<?= __('Copy Response') ?>" aria-label="<?= __('Copy Response') ?>">
                    <i class="far fa-copy"></i>
                </button>
                <button type="button" class="btn btn-sm btn-outline-secondary border-0" id="rest-response-download"
                        data-filename="<?= $isJson ? 'response.json' : 'response.txt' ?>"
                        title="<?= __('Download Response') ?>" aria-label="<?= __('Download Response') ?>">
                    <i class="fas fa-download"></i>
                </button>
            </div>
        <?php endif; ?>
    </div>

    <?php if (!$hasResponse): ?>
        <div class="card-body text-center text-body-secondary py-5">
            <i class="fas fa-satellite-dish fa-2x text-body-tertiary mb-3"></i>
            <p class="mb-0 small">
                <?= __('Send a request to see its status, body and headers here.') ?>
                <span class="d-none d-md-inline"><?= __('%s sends from anywhere on the page.', '<kbd>Ctrl</kbd> + <kbd>↵</kbd>') ?></span>
            </p>
        </div>
    <?php else: ?>
        <ul class="nav nav-tabs px-3" role="tablist">
            <li class="nav-item" role="presentation">
                <button type="button" role="tab" class="nav-link active" data-bs-toggle="tab" data-bs-target="#response-body"
                        aria-controls="response-body" aria-selected="true"><?= __('Body') ?></button>
            </li>
            <li class="nav-item" role="presentation">
                <button type="button" role="tab" class="nav-link d-flex align-items-center gap-2" data-bs-toggle="tab" data-bs-target="#response-headers"
                        aria-controls="response-headers" aria-selected="false">
                    <?= __('Headers') ?><span class="badge rounded-pill bg-body-secondary text-body-secondary"><?= count($responseHeaders) ?></span>
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button type="button" role="tab" class="nav-link d-flex align-items-center gap-2" data-bs-toggle="tab" data-bs-target="#response-cookies"
                        aria-controls="response-cookies" aria-selected="false">
                    <?= __('Cookies') ?><span class="badge rounded-pill bg-body-secondary text-body-secondary"><?= count($responseCookies) ?></span>
                </button>
            </li>
            <?php foreach ($snippets as $key => $snippet): ?>
                <li class="nav-item" role="presentation">
                    <button type="button" role="tab" class="nav-link" data-bs-toggle="tab" data-bs-target="#response-<?= $key ?>"
                            aria-controls="response-<?= $key ?>" aria-selected="false">
                        <i class="<?= $snippet['icon'] ?> me-1"></i><?= h($snippet['label']) ?>
                    </button>
                </li>
            <?php endforeach; ?>
        </ul>

        <div class="tab-content">
            <div class="tab-pane show active" id="response-body" role="tabpanel">
                <?php if ($showResult): ?>
                    <?= $codeBlock('response-body-code', $responseBody, $isJson) ?>
                <?php else: ?>
                    <pre class="d-none" id="response-body-code"><?= h($rawBody) ?></pre>
                    <div class="d-flex align-items-start gap-2 m-3 p-3 border rounded bg-body-tertiary small text-body-secondary">
                        <i class="fas fa-eye-slash mt-1"></i>
                        <span>
                            <strong class="text-body"><?= h($rawBody) ?></strong>
                            <?= __('The response body was not requested. Turn on Show result and send again to see it.') ?>
                        </span>
                    </div>
                <?php endif; ?>
            </div>

            <div class="tab-pane" id="response-headers" role="tabpanel">
                <div class="table-responsive">
                    <table class="table table-sm small mb-0">
                        <tbody>
                            <?php foreach ($responseHeaders as $key => $value): ?>
                                <tr>
                                    <td class="fw-semibold text-nowrap ps-3 w-25"><?= h($key) ?></td>
                                    <td class="font-monospace text-body-secondary text-break pe-3"><?= h(is_array($value) ? implode(', ', $value) : $value) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="tab-pane" id="response-cookies" role="tabpanel">
                <?php if (empty($responseCookies)): ?>
                    <div class="text-center text-body-secondary small p-4"><?= __('No cookies returned by the server.') ?></div>
                <?php else: ?>
                    <ul class="list-group list-group-flush small">
                        <?php foreach ($responseCookies as $cookie): ?>
                            <li class="list-group-item px-3 font-monospace text-break"><?= h($cookie) ?></li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            </div>

            <?php foreach ($snippets as $key => $snippet): ?>
                <div class="tab-pane position-relative" id="response-<?= $key ?>" role="tabpanel">
                    <button type="button" class="btn btn-sm btn-light border position-absolute top-0 end-0 m-2 z-1"
                            data-rest-copy="#<?= $key ?>-code"
                            data-rest-copied="<?= h(__('%s copied', $snippet['label'])) ?>"
                            title="<?= h(__('Copy %s', $snippet['label'])) ?>" aria-label="<?= h(__('Copy %s', $snippet['label'])) ?>">
                        <i class="far fa-copy"></i>
                    </button>
                    <?= $codeBlock($key . '-code', $snippet['code']) ?>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</section>
