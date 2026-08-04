<?php
/*
 *
 * Interactive correlation toggle in attribute context (table + card).
 *
 *  disable_correlation = false → correlation ON  → green fa-link
 *  disable_correlation = true  → correlation OFF → gray  fa-link-slash
 *
 * Non-correlating types are shown as a static badge (no toggle).
 * Falls back to a static boolean badge in non-attribute contexts.
 *
 */
$isCard    = isset($viewMode) && $viewMode === 'card';
$attribute = isset($row['Attribute']) ? $row['Attribute'] : $row;
$event     = isset($row['Event'])     ? $row['Event']     : $event;

if ($attribute && $event && isset($attribute['id'], $attribute['type'])):
    $objectId    = h($attribute['id']);
    $isNonCorrelatingType = in_array(
        $attribute['type'],
        MispAttribute::NON_CORRELATING_TYPES,
        true
    );
    $correlDisabled = !empty($attribute['disable_correlation']) || $isNonCorrelatingType;
    $canToggle      = $this->Acl->canDisableCorrelation($event)
                   && empty($event['disable_correlation'])
                   && !$isNonCorrelatingType;

    // ── Non-correlating type: purely static badge ─────────────────────────
    if ($isNonCorrelatingType):
?>
    <span class="badge text-bg-secondary d-inline-flex align-items-center gap-1"
          title="<?= __('Non-correlating type') ?>">
        <i class="fas fa-ban"></i>
        <?php if ($isCard): ?><?= __('N/A') ?><?php endif; ?>
    </span>

<?php
    // ── Correlation active/inactive toggle ────────────────────────────────
    elseif ($canToggle):
        $icon       = $correlDisabled ? 'fa-link-slash' : 'fa-link';
        $colorClass = $correlDisabled ? 'text-secondary' : 'text-success';
        $titleText  = $correlDisabled
            ? __('Correlation disabled — click to enable')
            : __('Correlation enabled — click to disable');
?>
    <button class="correlate-toggle btn btn-link p-0 border-0"
            id="correlate_btn_<?= $objectId ?>"
            data-attribute-id="<?= $objectId ?>"
            data-disable-correlation="<?= $correlDisabled ? '1' : '0' ?>"
            title="<?= $titleText ?>"
            aria-label="<?= $titleText ?>">

        <?php if ($isCard): ?>
            <span class="badge d-inline-flex align-items-center gap-1 px-2 py-1
                         border <?= $correlDisabled
                            ? 'border-secondary text-secondary'
                            : 'border-success text-success' ?>"
                  style="background:transparent;font-size:.8rem;">
                <i class="fas <?= $icon ?>"></i>
                <span class="correlate-label">
                    <?= $correlDisabled ? __('Correlation Off') : __('Correlation On') ?>
                </span>
            </span>
        <?php else: ?>
            <i class="fas <?= $icon ?> <?= $colorClass ?>" style="font-size:1.2em;"></i>
        <?php endif; ?>

    </button>

<?php
    // ── Read-only: user can see state but cannot toggle ───────────────────
    else:
        $icon       = $correlDisabled ? 'fa-link-slash' : 'fa-link';
        $colorClass = $correlDisabled ? 'text-secondary' : 'text-success';
        $titleText  = $correlDisabled ? __('Correlation disabled') : __('Correlation enabled');
?>
    <span id="correlate_btn_<?= $objectId ?>"
          data-disable-correlation="<?= $correlDisabled ? '1' : '0' ?>"
          title="<?= $titleText ?>">
        <?php if ($isCard): ?>
            <span class="badge d-inline-flex align-items-center gap-1 px-2 py-1
                         border <?= $correlDisabled
                            ? 'border-secondary text-secondary'
                            : 'border-success text-success' ?>"
                  style="background:transparent;font-size:.8rem;">
                <i class="fas <?= $icon ?>"></i>
                <span class="correlate-label">
                    <?= $correlDisabled ? __('Correlation Off') : __('Correlation On') ?>
                </span>
            </span>
        <?php else: ?>
            <i class="fas <?= $icon ?> <?= $colorClass ?>" style="font-size:1.2em;"></i>
        <?php endif; ?>
    </span>
<?php endif; ?>



<script>
(function () {
    if (window._correlateToggleInit) return;
    window._correlateToggleInit = true;

    /* PHP-translated labels */
    const _m = {
        titleDisable:  <?= json_encode(__('Disable correlation')) ?>,
        titleEnable:   <?= json_encode(__('Enable correlation')) ?>,
        descDisable:   <?= json_encode(__('This will remove all existing correlations for this attribute and prevents any new correlations as long as this setting is disabled. Make sure you understand the downsides of disabling correlations.')) ?>,
        descEnable:    <?= json_encode(__('Correlation will be re-enabled for this attribute.')) ?>,
        warnDisable:   <?= json_encode(__('Warning: this action cannot be undone automatically.')) ?>,
        cancel:        <?= json_encode(__('Cancel')) ?>,
        labelOn:       <?= json_encode(__('On')) ?>,
        labelOff:      <?= json_encode(__('Off')) ?>,
        savedEnabled:  <?= json_encode(__('Correlation enabled')) ?>,
        savedDisabled: <?= json_encode(__('Correlation disabled')) ?>,
        noChange:      <?= json_encode(__('Already up to date')) ?>,
        errPrefix:     <?= json_encode(__('Error')) ?>,
        errRequest:    <?= json_encode(__('Request failed — please try again')) ?>,
    };


    document.body.addEventListener('click', function (e) {
        const btn = e.target.closest('.correlate-toggle');
        if (!btn) return;
        e.preventDefault();

        const attrId   = btn.dataset.attributeId;
        const isDisabled = btn.dataset.disableCorrelation === '1';
        const willDisable = !isDisabled;

        /* Build modal body */
        const iconClass = willDisable ? 'text-secondary' : 'text-success';
        const iconName  = willDisable ? 'fa-link-slash'  : 'fa-link';
        const title     = willDisable ? _m.titleDisable  : _m.titleEnable;
        const desc      = willDisable ? _m.descDisable   : _m.descEnable;
        const btnClass  = willDisable ? 'btn-danger'     : 'btn-success';

        let bodyHtml =
            '<div class="d-flex align-items-start gap-3' + (willDisable ? ' mb-3' : '') + '">' +
                '<i class="fas ' + iconName + ' fa-2x mt-1 ' + iconClass + '"></i>' +
                '<p class="mb-0 text-muted small">' + escapeHtml(desc) + '</p>' +
            '</div>';

        /* Extra warning block when disabling */
        if (willDisable) {
            bodyHtml +=
                '<div class="alert alert-warning d-flex align-items-center gap-2 py-2 mb-0">' +
                    '<i class="fas fa-triangle-exclamation flex-shrink-0"></i>' +
                    '<small>' + escapeHtml(_m.warnDisable) + '</small>' +
                '</div>';
        }

        showConfirmModal({
            title:        title,
            body:         bodyHtml,
            confirmLabel: title,
            confirmClass: btnClass,
            cancelLabel:  _m.cancel,
            onConfirm:    function () {
                _doToggle(attrId, willDisable, btn);
            },
        });
    });

    /* AJAX call */
    async function _doToggle(attrId, willDisable, btn) {
        try {
            const response = await fetch(
                baseurl + '/attributes/toggleCorrelation/' + attrId,
                {
                    method:  'POST',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest',
                        'Content-Type':     'application/x-www-form-urlencoded',
                        'Accept':           'application/json',
                        'X-CSRF-Token':     getCsrfToken(),
                    },
                    body: '',
                }
            );

            const data = await response.json();

            if (data.saved) {
                _updateBtn(btn, willDisable);
                showToast(
                    willDisable ? _m.savedDisabled : _m.savedEnabled,
                    willDisable ? 'warning' : 'success'
                );
            } else if (data.errors && data.errors.value === 'nochange') {
                showToast(_m.noChange, 'info');
            } else {
                const detail = typeof data.errors === 'string'
                    ? data.errors
                    : JSON.stringify(data.errors);
                showToast(_m.errPrefix + ': ' + detail, 'danger');
            }
        } catch (_e) {
            showToast(_m.errRequest, 'danger');
        }
    }

    /* DOM update after a successful toggle */
    function _updateBtn(btn, nowDisabled) {
        btn.dataset.disableCorrelation = nowDisabled ? '1' : '0';
        btn.title = nowDisabled
            ? <?= json_encode(__('Correlation disabled — click to enable')) ?>
            : <?= json_encode(__('Correlation enabled — click to disable')) ?>;

        const icon  = btn.querySelector('.fa-link, .fa-link-slash');
        const badge = btn.querySelector('.badge');
        const label = btn.querySelector('.correlate-label');

        if (icon) {
            icon.classList.toggle('fa-link',       !nowDisabled);
            icon.classList.toggle('fa-link-slash',  nowDisabled);
            icon.classList.toggle('text-success',  !nowDisabled);
            icon.classList.toggle('text-secondary', nowDisabled);
        }
        if (badge) {
            badge.classList.toggle('border-success',   !nowDisabled);
            badge.classList.toggle('text-success',     !nowDisabled);
            badge.classList.toggle('border-secondary',  nowDisabled);
            badge.classList.toggle('text-secondary',    nowDisabled);
        }
        if (label) {
            label.textContent = nowDisabled ? _m.labelOff : _m.labelOn;
        }
    }
})();
</script>

<?php
else:
    // ── Static badge fallback — no Attribute/Event context ────────────────
    $correlate = Hash::extract($row, $field['data_path']);
    if (empty($correlate)) {
        $correlate[0] = false;
    }
    $boolean = !empty($field['boolean_reverse']) ? !$correlate[0] : $correlate[0];
    echo $this->element('genericElementsBS5/Badges/boolean', [
        'boolean'    => $boolean,
        'full'       => $isCard,
        'true'       => __('Correlation'),
        'false'      => __('No correlation'),
        'trueColor'  => 'success',
        'falseColor' => 'secondary',
        'trueIcon'   => 'fa-link',
        'falseIcon'  => 'fa-link-slash',
    ]);
endif;
?>
