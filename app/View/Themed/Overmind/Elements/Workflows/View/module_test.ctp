<?php
/*
 * Stateless execution: the module's exec() run once with parameters and
 * input typed here, through /workflows/moduleStatelessExecution.
 */
$params = $data['params'] ?? [];

$normaliseOptions = function (array $options) {
    if (!empty($options) && array_keys($options) === range(0, count($options) - 1)) {
        return isset($options[0]['name'], $options[0]['value'])
            ? array_column($options, 'name', 'value')
            : array_combine($options, $options);
    }
    return $options;
};
?>

<div class="row g-3" data-wf-module-test data-url="<?= h($baseurl . '/workflows/moduleStatelessExecution/' . $data['id']) ?>">
    <div class="col-lg-6">
        <div class="card shadow-sm h-100">
            <div class="card-header bg-transparent d-flex align-items-center gap-2 py-3">
                <i class="fas fa-sliders text-secondary"></i>
                <span class="fw-semibold"><?= __('Module parameters') ?></span>
            </div>
            <div class="card-body d-flex flex-column gap-3">
                <?php if (empty($params)): ?>
                    <p class="text-muted small mb-0"><?= __('This module takes no parameter.') ?></p>
                <?php endif; ?>
                <?php foreach ($params as $i => $param): ?>
                    <?php
                    $inputId = 'wfParam' . $i;
                    $type = $param['type'] ?? 'input';
                    $default = $param['default'] ?? null;
                    $multiple = !empty($param['multiple']);
                    $options = $normaliseOptions($param['options'] ?? []);
                    $optionsUrl = $param['picker_options']['select_options_url'] ?? null;
                    $common = sprintf(
                        'id="%s" data-param="%s"%s',
                        h($inputId),
                        h($param['id']),
                        $multiple ? ' data-multiple="1"' : ''
                    );
                    ?>
                    <div>
                        <label class="form-label small fw-semibold mb-1" for="<?= h($inputId) ?>">
                            <?= h($param['label'] ?? $param['id']) ?>
                            <?php if (!empty($param['jinja_supported'])): ?>
                                <span class="badge rounded-pill text-bg-info fw-normal ms-1">Jinja2</span>
                            <?php endif; ?>
                        </label>
                        <?php if ($type === 'select' || $type === 'picker'): ?>
                            <select class="form-select tom-select" <?= $common ?>
                                    <?= $multiple ? 'multiple' : '' ?>
                                    <?= $optionsUrl ? 'data-options-url="' . h($baseurl . $optionsUrl) . '"' : '' ?>
                                    data-placeholder="<?= h($param['placeholder'] ?? __('Pick a value')) ?>">
                                <?php if (!$multiple): ?>
                                    <option value=""></option>
                                <?php endif; ?>
                                <?php foreach ($options as $value => $label): ?>
                                    <?php $selected = $multiple
                                        ? in_array((string)$value, array_map('strval', (array)$default), true)
                                        : (string)$value === (string)$default; ?>
                                    <option value="<?= h($value) ?>" <?= $selected ? 'selected' : '' ?>><?= h($label) ?></option>
                                <?php endforeach; ?>
                            </select>
                        <?php elseif ($type === 'textarea'): ?>
                            <textarea class="form-control font-monospace small" rows="4" <?= $common ?>
                                      placeholder="<?= h($param['placeholder'] ?? '') ?>"><?= h(is_string($default) ? $default : '') ?></textarea>
                        <?php else: ?>
                            <input type="text" class="form-control<?= $type === 'hashpath' ? ' font-monospace' : '' ?>" <?= $common ?>
                                   placeholder="<?= h($param['placeholder'] ?? '') ?>"
                                   value="<?= h(is_scalar($default) ? $default : '') ?>">
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <div class="col-lg-6">
        <div class="card shadow-sm h-100">
            <div class="card-header bg-transparent d-flex align-items-center gap-2 py-3">
                <i class="fas fa-right-to-bracket text-secondary"></i>
                <span class="fw-semibold"><?= __('Input data') ?></span>
            </div>
            <div class="card-body d-flex flex-column gap-3">
                <?= $this->element('genericElementsBS5/Forms/json_field', [
                    'field' => false,
                    'id' => 'wfModuleInput',
                    'label' => __('Data passed to the module'),
                    'placeholder' => '{"Event": {"info": "…", "Attribute": []}}',
                    'rows' => 12,
                    'hint' => __('Empty means an empty document.'),
                ]) ?>
                <div class="form-check form-switch">
                    <input class="form-check-input" type="checkbox" id="wfModuleConvert" checked>
                    <label class="form-check-label small" for="wfModuleConvert">
                        <?= __('Convert the input into MISP core format first') ?>
                    </label>
                </div>
            </div>
        </div>
    </div>

    <div class="col-12">
        <div class="card shadow-sm">
            <div class="card-header bg-transparent d-flex align-items-center justify-content-between py-3">
                <div class="d-flex align-items-center gap-2">
                    <i class="fas fa-terminal text-secondary"></i>
                    <span class="fw-semibold"><?= __('Execution result') ?></span>
                    <span class="badge rounded-pill text-bg-secondary" data-wf-result-status><?= __('not executed') ?></span>
                </div>
                <button type="button" class="btn btn-primary btn-sm" data-wf-run>
                    <span class="spinner-border spinner-border-sm me-1 d-none" data-wf-spinner></span>
                    <i class="fas fa-play me-1" data-wf-run-icon></i><?= __('Execute module') ?>
                </button>
            </div>
            <div class="card-body">
                <div class="alert alert-warning small py-2 d-flex gap-2 align-items-start">
                    <i class="fas fa-triangle-exclamation mt-1"></i>
                    <span><?= __('The module really runs: an action module sends its mails, calls its webhooks and edits the data it is given.') ?></span>
                </div>
                <div class="d-none" data-wf-result-errors></div>
                <pre class="bg-body-tertiary border rounded p-3 small mb-0" style="max-height:420px;overflow:auto;" data-wf-result-text><?= __('- not executed -') ?></pre>
            </div>
        </div>
    </div>
</div>

<script>
(function () {
    function init() {
        var root = document.querySelector('[data-wf-module-test]');
        if (!root || root.dataset.bound) return;
        root.dataset.bound = '1';

        var runButton = root.querySelector('[data-wf-run]');
        var spinner = root.querySelector('[data-wf-spinner]');
        var runIcon = root.querySelector('[data-wf-run-icon]');
        var status = root.querySelector('[data-wf-result-status]');
        var resultText = root.querySelector('[data-wf-result-text]');
        var resultErrors = root.querySelector('[data-wf-result-errors]');

        initTomSelect(root);

        root.querySelectorAll('select[data-options-url]').forEach(function (select) {
            fetch(select.dataset.optionsUrl, {
                headers: {'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'},
                credentials: 'same-origin'
            })
                .then(function (response) { return response.ok ? response.json() : Promise.reject(response); })
                .then(function (options) {
                    var ts = select.tomselect;
                    (Array.isArray(options) ? options : Object.values(options)).forEach(function (option) {
                        var value = typeof option === 'object' ? (option.value || option.name) : option;
                        if (ts) {
                            ts.addOption({value: value, text: value});
                        } else {
                            select.add(new Option(value, value));
                        }
                    });
                    if (ts) ts.refreshOptions(false);
                })
                .catch(function () {
                    showToast(<?= json_encode(__('Could not load the options of a parameter.')) ?>, 'danger');
                });
        });

        function collect() {
            var body = new URLSearchParams();
            root.querySelectorAll('[data-param]').forEach(function (el) {
                var key = 'module_indexed_param[' + el.dataset.param + ']';
                if (el.multiple) {
                    Array.from(el.selectedOptions).forEach(function (option) {
                        body.append(key + '[]', option.value);
                    });
                } else {
                    body.append(key, el.value);
                }
            });
            var input = document.getElementById('wfModuleInput').value.trim();
            body.append('input_data', input === '' ? '{}' : input);
            body.append('convert_data', document.getElementById('wfModuleConvert').checked ? '1' : '0');
            return body;
        }

        function setLoading(loading) {
            runButton.disabled = loading;
            spinner.classList.toggle('d-none', !loading);
            runIcon.classList.toggle('d-none', loading);
        }

        function show(httpStatus, duration, result) {
            var ok = httpStatus === 200 && result && typeof result === 'object' && result.success;
            status.className = 'badge rounded-pill ' + (ok ? 'text-bg-success' : 'text-bg-danger');
            status.textContent = (ok ? <?= json_encode(__('success')) ?> : <?= json_encode(__('failure')) ?>)
                + ' · ' + httpStatus + ' · ' + duration + ' ms';

            var errors = result && typeof result === 'object'
                ? [].concat(result.errors || [], result.error || [])
                : [];
            resultErrors.replaceChildren();
            resultErrors.classList.toggle('d-none', errors.length === 0);
            if (errors.length) {
                var list = document.createElement('ul');
                list.className = 'alert alert-danger small mb-3 ps-4';
                errors.forEach(function (error) {
                    var item = document.createElement('li');
                    item.textContent = typeof error === 'string' ? error : JSON.stringify(error);
                    list.appendChild(item);
                });
                resultErrors.appendChild(list);
            }
            resultText.textContent = typeof result === 'string'
                ? result
                : JSON.stringify(result, null, 2);
        }

        runButton.addEventListener('click', function () {
            var input = document.getElementById('wfModuleInput').value.trim();
            if (input !== '') {
                try {
                    JSON.parse(input);
                } catch (e) {
                    showToast(<?= json_encode(__('The input data is not valid JSON.')) ?>, 'danger');
                    return;
                }
            }
            var started = Date.now();
            setLoading(true);
            fetch(root.dataset.url, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRF-Token': getCsrfToken(),
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: collect().toString()
            })
                .then(function (response) {
                    return response.text().then(function (text) {
                        var parsed = text;
                        try { parsed = JSON.parse(text); } catch (e) {}
                        show(response.status, Date.now() - started, parsed);
                    });
                })
                .catch(function (error) {
                    show(0, Date.now() - started, String(error));
                })
                .finally(function () { setLoading(false); });
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
</script>
