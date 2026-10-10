<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

/**
 * HTML templates for plugin modals, tables, buttons, and UI feedback states.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.View.Elements.Common
 */
?>

<?= $this->Html->css(MsgdPluginFileEnum::msgd_style_css->getPath(), ['inline' => true]); ?>

<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */
/* Main modal to select groups and configure the blueprint */ ?>
<script type="text/template" id="tpl-msgd-modal-blueprint">
    <div id="msgdBlueprintModal" class="modal hide fade msgd-modal" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-header">
            <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
            <h3 id="msgdModalLabel"><?= h(__d('msgd_plug', 'Multiple Sharing Groups')); ?></h3>
        </div>
        <div class="modal-body msgd-modal-body">
            <div class="control-group msgd-control-group">
                <label class="control-label msgd-label"><?= h(__d('msgd_plug', 'Available Sharing Groups')); ?></label>
                <div class="controls">
                    <div id="msgdGroupsContainer"></div>
                </div>
            </div>
            <div id="msgdAdvancedContainer" class="msgd-advanced-container">
                <a href="#" id="msgdAdvancedToggleBtn" class="msgd-advanced-toggle-btn">
                    <i class="fas fa-caret-right" id="msgdAdvancedIcon"></i> <?= h(
                            __d('msgd_plug', 'Advanced Options')
                    ); ?>
                </a>
                <div id="nameInputWrapperMsgd" class="control-group msgd-control-group-name">
                    <label class="control-label msgd-label">
                        <?= h(__d('msgd_plug', 'Optional combinative sharing group name (Blueprint)')); ?>
                    </label>
                    <div class="controls">
                        <input type="text" id="blueprintNameInputMsgd" class="input-block-level"
                               placeholder="<?= h(__d('msgd_plug', 'Blueprint Name (auto-generated...)')); ?>">
                    </div>
                </div>
            </div>
        </div>
        <div class="modal-footer msgd-modal-footer">
            <div id="msgdSelectionStatus"
                 class="msgd-selection-status">
                <button type="button" id="msgdSelectionStatusBtn" class="msgd-selection-status-btn"
                        aria-label="<?= h(__d('msgd_plug', 'Status')); ?>"
                        title="<?= h(__d('msgd_plug', 'Status')); ?>">
                    <i class="fas fa-exclamation-triangle"></i>
                </button>
                <div id="msgdSelectionStatusMessage" class="msgd-selection-status-message">
                </div>
            </div>
            <button type="button" class="btn" data-dismiss="modal" aria-hidden="true">
                <?= h(__d('msgd_plug', 'Cancel')); ?>
            </button>
            <button type="button" id="msgdExecuteBtn" class="btn btn-primary">
                <?= h(__d('msgd_plug', 'Select')); ?>
            </button>
        </div>
    </div>
</script>

<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */
/* Main trigger button that opens the group selection modal */ ?>
<script type="text/template" id="tpl-msgd-button">
    <div class="msgd-button-wrapper">
        <button type="button" id="msgdLaunchModalBtn" class="btn btn-inverse" data-toggle="modal"
                data-target="#msgdBlueprintModal">
            <i class="fas fa-cog"></i> <?= h(__d('msgd_plug', 'Select Sharing Groups')); ?>
        </button>
        <div id="msgdInfoGroupsContainer" class="msgd-info-groups-container"></div>
    </div>
</script>

<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */
/* Operations toolbar with search filter and toggle option */ ?>
<script type="text/template" id="tpl-msgd-operation-toolbar">
    <div class="msgd-operation-toolbar">
        <div class="msgd-search-box">
            <input type="text" id="msgdSearchInput" class="input-block-level msgd-search-input"
                   placeholder="<?= h(__d('msgd_plug', 'Search groups...')); ?>">
            <button type="button" id="msgdResetBtn" class="btn btn-small msgd-btn-reset">
                <i class="fas fa-sync-alt"></i> <?= h(__d('msgd_plug', 'Reset')); ?>
            </button>
        </div>
        <div class="msgd-toolbar-options">
            <label class="checkbox inline msgd-toggle-label">
                <input type="checkbox" id="msgdToggleAllGroups" {{SHOW_ALL_CHECKED}}>
                <?= h(__d('msgd_plug', 'Show all groups')); ?>
            </label>
        </div>
    </div>
</script>

<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */
/* Wrapper container uniting the operations toolbar and content view */ ?>
<script type="text/template" id="tpl-msgd-operation-wrapper">
    <div class="msgd-operation-wrapper">
        {{TOOLBAR}}
        <div class="msgd-operation-container">
            {{CONTENT}}
        </div>
    </div>
</script>

<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */
/* Table structure for listing available sharing groups with checkboxes */ ?>
<script type="text/template" id="tpl-msgd-operation-table">
    <table class="msgd-operation-table">
        <thead>
        <tr>
            <th class="msgd-col-checkbox">#</th>
            <th class="msgd-col-name"><?= h(__d('msgd_plug', 'Sharing Group Name')); ?></th>
        </tr>
        </thead>
        <tbody>{{ROWS}}</tbody>
    </table>
</script>

<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */
/* Individual table row with a group selection checkbox */ ?>
<script type="text/template" id="tpl-msgd-operation-row">
    <tr class="msgd-checkbox-item msgd-operation-row">
        <td class="msgd-col-checkbox">
            <input type="checkbox" value="{{VALUE}}" data-name="{{NAME}}"
                   class="group-checkbox-msgd msgd-checkbox-input" {{CHECKED}}>
        </td>
        <td class="msgd-col-name">{{NAME}}</td>
    </tr>
</script>

<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */
/* Overview modal displaying associated sharing group details */ ?>
<script type="text/template" id="tpl-msgd-modal-view">
    <div id="msgdViewModal" class="modal hide fade msgd-modal" tabindex="-1" role="dialog"
         aria-labelledby="msgdViewModalLabel" aria-hidden="true">
        <div class="modal-header">
            <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
            <h3 id="msgdViewModalLabel"><?= h(__d('msgd_plug', 'Sharing Groups Overview')); ?></h3>
        </div>
        <div class="modal-body msgd-modal-body" id="msgdViewModalBody"></div>
        <div class="modal-footer">
            <button type="button" class="btn" data-dismiss="modal" aria-hidden="true">
                <?= h(__d('msgd_plug', 'Close')); ?>
            </button>
        </div>
    </div>
</script>

<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */
/* Summary info table displaying total count and selected group list */ ?>
<script type="text/template" id="tpl-msgd-info-table">
    <table class="msgd-info-table">
        <thead>
        <tr>
            <th class="msgd-col-idx">#</th>
            <th class="msgd-col-name">
                <span class="msgd-table-title"><?= h(__d('msgd_plug', 'Sharing Groups')); ?> ({{COUNT}})</span>
                {{HEADER_ACTIONS}}
            </th>
        </tr>
        </thead>
        <tbody>{{ROWS}}</tbody>
    </table>
</script>

<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */
/* Header action controls for panel locking/dragging or collapsing */ ?>
<script type="text/template" id="tpl-msgd-header-actions">
    <div class="msgd-header-actions">
        <button type="button" class="msgd-drag-toggle-btn"
                title="<?= h(__d('msgd_plug', 'Move Disabled (Click to activate)')); ?>">
            <i class="fas fa-lock"></i>
        </button>
        <button type="button" class="msgd-collapse-toggle-btn" title="<?= h(__d('msgd_plug', 'Expand/Collapse')); ?>">
            <i class="fas fa-chevron-down msgd-toggle-icon"></i>
        </button>
    </div>
</script>

<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */
/* Primary/Main sharing group row layout */ ?>
<script type="text/template" id="tpl-msgd-info-main-row">
    <tr class="msgd-row-main">
        <td class="msgd-col-idx">main</td>
        <td class="msgd-col-name">
            <span title="{{FULL_NAME}}">{{TRUNCATED_NAME}}</span> {{EYE_BTN}}
        </td>
    </tr>
</script>

<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */
/* Standard row layout for secondary sharing groups */ ?>
<script type="text/template" id="tpl-msgd-info-row">
    <tr>
        <td class="msgd-col-idx">{{IDX}}</td>
        <td class="msgd-col-name">
            <span title="{{FULL_NAME}}">{{TRUNCATED_NAME}}</span> {{EYE_BTN}}
        </td>
    </tr>
</script>

<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */
/* Action icon button to open sharing group details in a new browser tab */ ?>
<script type="text/template" id="tpl-msgd-sg-eye-btn">
    <a href="{{VIEW_URL}}" target="_blank" rel="noopener noreferrer" class="msgd-sg-info-btn"
       title="<?= h(__d('msgd_plug', 'View Sharing Group Details')); ?>">
        <i class="fas fa-eye"></i>
    </a>
</script>

<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */
/* Compact button for index views that triggers the groups modal */ ?>
<script type="text/template" id="tpl-msgd-index-view-btn">
    <button type="button" class="btn btn-mini btn-info msgd-index-view-btn" data-sg-id="{{SG_ID}}"
            data-sg-name="{{SG_NAME}}">
        <?= h(__d('msgd_plug', 'View Groups')); ?>
    </button>
</script>

<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */
/* Loading indicator state (spinner animation) */ ?>
<script type="text/template" id="tpl-msgd-feedback-loading">
    <div class="msgd-feedback-loading">
        <i class="fas fa-spinner fa-spin"></i> <?= h(__d('msgd_plug', 'Loading...')); ?>
    </div>
</script>

<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */
/* Empty feedback message when no items match */ ?>
<script type="text/template" id="tpl-msgd-feedback-empty">
    <div class="msgd-feedback-empty">{{MESSAGE}}</div>
</script>

<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */
/* Error feedback container for UI or API failures */ ?>
<script type="text/template" id="tpl-msgd-feedback-error">
    <div class="msgd-feedback-error">{{MESSAGE}}</div>
</script>
