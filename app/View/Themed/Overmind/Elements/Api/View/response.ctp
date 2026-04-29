<?php
$responseBody = $data['data'] ?? '';
$responseHeaders = $data['headers'] ?? [];
$responseCode = $data['code'] ?? null;
$responseDuration = $data['duration'] ?? null;

// For better readability, we pretty-print JSON responses when possible
$decodedBody = json_decode($responseBody);
if (json_last_error() === JSON_ERROR_NONE && !empty($responseBody)) {
    $responseBody = json_encode($decodedBody, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
}

// Extracting cookies from response headers (looking for 'Set-Cookie')
$responseCookies = [];
foreach ($responseHeaders as $key => $value) {
    if (strtolower($key) === 'set-cookie') {
        $responseCookies = is_array($value) ? $value : [$value];
    }
}


// Coloration logic for response code badge
$codeClass = null;
$codeText = '';
if ($responseCode !== null) {
    if ($responseCode >= 200 && $responseCode < 300) {
        $codeClass = 'badge bg-success';
        $codeText = 'OK';
    } elseif ($responseCode >= 400 && $responseCode < 500) {
        $codeClass = 'badge bg-danger';
        $codeText = 'ERROR';
    }
}
?>

<div class="card shadow-sm mb-4">
    <div class="card-header bg-light d-flex justify-content-between align-items-end pt-2 pb-0 px-3">
        <ul class="nav nav-tabs card-header-tabs mb-0">
            <li class="nav-item">
                <a class="nav-link active small py-2 px-3" data-bs-toggle="tab" href="#response-body">Body</a>
            </li>
            <li class="nav-item">
                <a class="nav-link small py-2 px-3" data-bs-toggle="tab" href="#response-headers">Headers</a>
            </li>
            <li class="nav-item">
                <a class="nav-link small py-2 px-3" data-bs-toggle="tab" href="#response-cookies">Cookies</a>
            </li>
        </ul>

        <div class="d-flex align-items-center gap-3 pb-2">
            <?php if ($responseCode): ?>
                <span class="<?= $codeClass ?>">
                    <?= h($responseCode) ?> <?= h($codeText) ?>
                </span>
            <?php endif; ?>

            <?php if ($responseDuration): ?>
                <span class="small text-secondary fw-medium">
                    <?= h($responseDuration) ?>
                </span>
            <?php endif; ?>

            <div class="d-flex gap-2">
                <button class="btn btn-sm text-secondary p-0 border-0 shadow-none hover-dark" onclick="copyCode('response-body-code')" title="Copier">
                    <i class="fas fa-copy"></i>
                </button>
                <button class="btn btn-sm text-secondary p-0 border-0 shadow-none hover-dark" onclick="downloadResponse()" title="Télécharger">
                    <i class="fas fa-download"></i>
                </button>
            </div>
        </div>
    </div>

    <div class="card-body p-0 border-0">
        <div class="tab-content">
            <div class="tab-pane fade show active" id="response-body">
                <pre id="response-body-code" class="bg-dark p-3 m-0 font-monospace overflow-auto rounded-bottom custom-code-text"><?= h($responseBody) ?></pre>
            </div>

            <div class="tab-pane fade p-3" id="response-headers">
                <table class="table table-sm mb-0">
                    <tbody>
                        <?php foreach ($responseHeaders as $key => $value): ?>
                            <tr>
                                <td class="fw-semibold text-nowrap w-25"><?= h($key) ?></td>
                                <td class="text-break"><?= is_array($value) ? implode(', ', $value) : h($value) ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <div class="tab-pane fade p-3" id="response-cookies">
                <?php if (empty($responseCookies)): ?>
                    <div class="text-muted small">No cookies returned by the server.</div>
                <?php else: ?>
                    <ul class="list-group list-group-flush mb-0 small">
                        <?php foreach ($responseCookies as $cookie): ?>
                            <li class="list-group-item px-0 bg-transparent text-break text-monospace">
                                <?= h($cookie) ?>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>