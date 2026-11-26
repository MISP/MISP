<?php
/*
 *
 * Interactive shield button in attribute context (table + card).
 * - Orange shield : IDS active
 * - Gray shield   : IDS inactive
 *
 * Falls back to a static badge via data_path in other contexts.
 */
$isCard    = isset($viewMode) && $viewMode === 'card';
$attribute = isset($row['Attribute']) ? $row['Attribute'] : $row;

if ($attribute && isset($attribute['id'], $attribute['to_ids'])):
    $objectId  = h($attribute['id']);
    $toIds     = !empty($attribute['to_ids']);
    $mayModify = isset($event) ? $this->Acl->canModifyEvent($event) : $this->Acl->canModifyEvent($row);

    $colorClass = $toIds ? 'text-warning' : 'text-secondary';
    $titleText  = $toIds
        ? __('IDS active — click to disable')
        : __('IDS inactive — click to enable');
?>

<?php if ($mayModify): ?>
    <button class="ids-shield-toggle btn btn-link p-0 border-0"
            id="ids_shield_<?= $objectId ?>"
            data-attribute-id="<?= $objectId ?>"
            data-to-ids="<?= $toIds ? '1' : '0' ?>"
            title="<?= $titleText ?>"
            aria-label="<?= $titleText ?>">
<?php else: ?>
    <span id="ids_shield_<?= $objectId ?>"
          data-to-ids="<?= $toIds ? '1' : '0' ?>"
          title="<?= $toIds ? __('IDS active') : __('IDS inactive') ?>">
<?php endif; ?>

    <?php if ($isCard): ?>
        <span class="badge d-inline-flex align-items-center gap-1 px-2 py-1
                     border <?= $toIds ? 'border-warning text-warning' : 'border-secondary text-secondary' ?>"
              style="background:transparent;font-size:.8rem;">
            <i class="fas fa-shield-halved"></i>
            <span class="ids-label"><?= $toIds ? __('IDS') : __('No IDS') ?></span>
        </span>
    <?php else: ?>
        <i class="fas fa-shield-halved <?= $colorClass ?>" style="font-size:1.2em;"></i>
    <?php endif; ?>

<?php if ($mayModify): ?>
    </button>
<?php else: ?>
    </span>
<?php endif; ?>


<?php
if (empty($this->viewVars['_idsShieldScriptEmitted'])):
    $this->viewVars['_idsShieldScriptEmitted'] = true;
?>

<script>
(function () {
    if (window._idsShieldInit) return;
    window._idsShieldInit = true;

    /* Translated labels injected by PHP */
    const _m = {
        titleEnable:  <?= json_encode(__('Enable IDS')) ?>,
        titleDisable: <?= json_encode(__('Disable IDS')) ?>,
        descEnable:   <?= json_encode(__('This attribute will be sent to IDS/detection tools.')) ?>,
        descDisable:  <?= json_encode(__('This attribute will no longer be sent to IDS/detection tools.')) ?>,
        cancel:       <?= json_encode(__('Cancel')) ?>,
        idsOn:        <?= json_encode(__('IDS')) ?>,
        idsOff:       <?= json_encode(__('No IDS')) ?>,
        savedOn:      <?= json_encode(__('IDS flag enabled')) ?>,
        savedOff:     <?= json_encode(__('IDS flag disabled')) ?>,
        noChange:     <?= json_encode(__('Already up to date')) ?>,
        errPrefix:    <?= json_encode(__('Error')) ?>,
        errRequest:   <?= json_encode(__('Request failed — please try again')) ?>,
    };

    /* Click handler (event delegation) */
    document.body.addEventListener('click', function (e) {
        const btn = e.target.closest('.ids-shield-toggle');
        if (!btn) return;
        e.preventDefault();

        const attrId    = btn.dataset.attributeId;
        const toIds     = btn.dataset.toIds === '1';
        const isEnable  = !toIds;
        const title     = isEnable ? _m.titleEnable  : _m.titleDisable;
        const desc      = isEnable ? _m.descEnable   : _m.descDisable;
        const btnClass  = isEnable ? 'btn-warning'   : 'btn-secondary';
        const iconClass = isEnable ? 'text-warning'  : 'text-secondary';

        const bodyHtml =
            '<div class="d-flex align-items-start gap-3">' +
                '<i class="fas fa-shield-halved fa-2x mt-1 ' + iconClass + '"></i>' +
                '<p class="mb-0 text-muted small">' + escapeHtml(desc) + '</p>' +
            '</div>';

        showConfirmModal({
            title:        title,
            body:         bodyHtml,
            confirmLabel: title,
            confirmClass: btnClass,
            cancelLabel:  _m.cancel,
            onConfirm:    function () {
                _doToggle(attrId, toIds ? '0' : '1', btn);
            },
        });
    });

    /* Toggle function for IDS flags */
    async function _doToggle(attrId, newVal, btn) {
        const isOn = newVal === '1';
        try {
            const response = await fetch(baseurl + '/attributes/editField/' + attrId, {
                method:  'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'Content-Type':     'application/x-www-form-urlencoded',
                    'Accept':           'application/json',
                    'X-CSRF-Token':     getCsrfToken(),
                },
                body: 'Attribute[to_ids]=' + encodeURIComponent(newVal),
            });

            const data = await response.json();

            if (data.saved) {
                _updateShield(btn, isOn);
                showToast(isOn ? _m.savedOn : _m.savedOff, 'success');
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
    function _updateShield(btn, isOn) {
        // One attribute can be on screen more than once — the object index
        // renders its list view and its card view at the same time — so every
        // copy of the shield has to follow, not just the one that was clicked.
        const attrId = btn.dataset.attributeId;
        const all = attrId
            ? document.querySelectorAll('.ids-shield-toggle[data-attribute-id="' + attrId + '"]')
            : [btn];
        all.forEach(function (el) { _paintShield(el, isOn); });
    }

    function _paintShield(btn, isOn) {
        btn.dataset.toIds = isOn ? '1' : '0';
        btn.title = isOn
            ? <?= json_encode(__('IDS active — click to disable')) ?>
            : <?= json_encode(__('IDS inactive — click to enable')) ?>;

        const icon  = btn.querySelector('.fa-shield-halved');
        const badge = btn.querySelector('.badge');
        const label = btn.querySelector('.ids-label');

        if (icon) {
            icon.classList.toggle('text-warning',   isOn);
            icon.classList.toggle('text-secondary', !isOn);
        }
        if (badge) {
            badge.classList.toggle('border-warning',   isOn);
            badge.classList.toggle('text-warning',     isOn);
            badge.classList.toggle('border-secondary', !isOn);
            badge.classList.toggle('text-secondary',   !isOn);
        }
        if (label) {
            label.textContent = isOn ? _m.idsOn : _m.idsOff;
        }
    }
})();
</script>
<?php endif; ?>

<?php
else:
    // Static badge fallback — no Attribute context (used in other index views)
    $ids = Hash::extract($row, $field['data_path']);
    if (empty($ids)) return;
    $boolean = !empty($field['boolean_reverse']) ? !$ids[0] : $ids[0];
    echo $this->element('genericElementsBS5/Badges/boolean', [
        'boolean'    => $boolean,
        'full'       => $isCard,
        'true'       => __('IDS'),
        'false'      => __('No IDS'),
        'trueColor'  => 'warning',
        'falseColor' => 'secondary',
        'trueIcon'   => 'fa-shield-halved',
        'falseIcon'  => 'fa-shield-halved',
    ]);
endif;
?>
