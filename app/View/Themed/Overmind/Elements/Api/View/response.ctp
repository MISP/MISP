<!-- =======================================================
Still in work 
======================================================= -->

<?php

$responseBody = $data['data'] ?? '';
$responseHeaders = $data['headers'] ?? [];
$responseCode = $data['code'] ?? null;
$responseDuration = $data['duration'] ?? null;

?>

<div class="response-container">
    <!-- TOP BAR -->
    <div class="response-topbar">
        <ul class="nav nav-tabs response-tabs">
            <li class="nav-item">
                <a class="nav-link active" data-bs-toggle="tab" href="#response-body">
                    Body
                </a>
            </li>

            <li class="nav-item">
                <a class="nav-link" data-bs-toggle="tab" href="#response-headers">
                    Headers
                </a>
            </li>

            <li class="nav-item">
                <a class="nav-link" data-bs-toggle="tab" href="#response-cookies">
                    Cookies
                </a>
            </li>
        </ul>

        <div class="response-meta">
            <?php if ($responseCode): ?>
                <span class="badge bg-success">
                    <?= h($responseCode) ?> OK
                </span>
            <?php endif; ?>

            <?php if ($responseDuration): ?>
                <span class="response-time">
                    <?= h($responseDuration) ?>
                </span>
            <?php endif; ?>

            <button class="icon-btn" onclick="copyCode('response-body-code')">
                <i class="fas fa-copy"></i>
            </button>

            <button class="icon-btn" onclick="downloadResponse()">
                <i class="fas fa-download"></i>
            </button>
        </div>
    </div>

    <!-- TAB CONTENT -->
    <div class="tab-content">
        <!-- BODY -->
        <div class="tab-pane fade show active" id="response-body">
            <pre id="response-body-code" class="response-code">
                <?= h($responseBody) ?>
            </pre>
        </div>

        <!-- HEADERS -->
        <div class="tab-pane fade" id="response-headers">
            <table class="table table-sm">
                <tbody>
                    <?php foreach ($responseHeaders as $key => $value): ?>
                        <tr>
                            <td class="fw-bold"><?= h($key) ?></td>
                            <td><?= is_array($value) ? implode(', ', $value) : h($value) ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <!-- COOKIES -->
        <div class="tab-pane fade" id="response-cookies">
            <div class="text-muted">
                No cookies returned
            </div>
        </div>
    </div>
</div>


<script>
    function copyCode(id){
        const code = document.getElementById(id).innerText;

        navigator.clipboard.writeText(code);

    }

    function downloadResponse(){
        const text = document.getElementById("response-body-code").innerText;

        const blob = new Blob([text], {type:"application/json"});

        const url = URL.createObjectURL(blob);

        const a = document.createElement("a");

        a.href = url;
        a.download = "response.json";
        a.click();

        URL.revokeObjectURL(url);

    }
</script>