<?php
/**
 * Global overlay containers for the Overmind chrome.
 *
 * Shared by Layouts/default.ctp and Layouts/dashboard.ctp, which each used to
 * carry their own copy of this block.
 *
 * Three sets live here:
 *
 *  - Shared. #popover_form, #confirmation_box, #gray_out and .loading are
 *    driven by both stacks — mispOvermind.js (getPopup / confirm / loading
 *    overlay) and legacy misp.js.
 *
 *  - BS5 only. #mainModal and #mainToastContainer are mispOvermind.js's own
 *    surfaces; #api-tooltip is restOvermind.js's (api/rest). misp.js knows
 *    nothing about them.
 *
 *  - Legacy only. #popover_form_large, #popover_form_x_large,
 *    #popover_matrix, #popover_box, #ajax_success and #ajax_fail are read by
 *    misp.js, attack_matrix.js and decayingToolBasescore.js — none of which
 *    a BS5 page loads. They were previously emitted on every page as dead
 *    markup. This mirrors the container block of the core
 *    app/View/Layouts/default.ctp, which the legacy branch's JS was written
 *    against.
 *
 * Parameters:
 *  - legacy  bool  emit the misp.js-only containers instead of the BS5 ones
 */
$legacy = !empty($legacy);
?>
<div id="popover_form" class="ajax_popover_form"></div>
<div id="confirmation_box"></div>
<div id="gray_out"></div>
<?php if ($legacy): ?>
<div id="popover_form_large" class="ajax_popover_form ajax_popover_form_large"></div>
<div id="popover_form_x_large" class="ajax_popover_form ajax_popover_form_x_large"></div>
<div id="popover_matrix" class="ajax_popover_form ajax_popover_matrix"></div>
<div id="popover_box" class="popover_box"></div>
<div id="ajax_success_container" class="ajax_container">
    <div id="ajax_success" class="ajax_result ajax_success"></div>
</div>
<div id="ajax_fail_container" class="ajax_container">
    <div id="ajax_fail" class="ajax_result ajax_fail"></div>
</div>
<?php else: ?>
<div class="modal fade" id="mainModal" tabindex="-1">
    <div class="modal-dialog modal-dialog-centered" id="dynamicModalDialog">
        <div class="modal-content border-0" style="margin: auto;">
            <div class="modal-body p-0 m-0" id="mainModalBody"></div>
        </div>
    </div>
</div>
<div id="mainToastContainer" class="main-toast-container"></div>
<div id="api-tooltip" class="api-tooltip"></div>
<?php endif; ?>
<div class="loading">
    <div class="spinner"></div>
    <div class="loadingText"><?= __('Loading') ?></div>
</div>
