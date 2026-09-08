<?php
// Proposal rows are not selectable for mass actions 
if (!empty($row['is_proposal']) || !empty($row['Attribute']['is_proposal'])) {
    return;
}

$id = Hash::get($row, $field['data_path']);
if (empty($id)) {
    if (!empty($row['id'])) {
        $id = $row['id'];
    }
}

$checkboxAttrs = [
    'type' => 'checkbox',
    'class' => 'item-checkbox form-check-input mass-select mt-0'
];

if (isset($field['publish_path'])) {
    $checkboxAttrs['data-publish'] = Hash::get($row, $field['publish_path']) ? '1' : '0';
}

if (isset($field['enable_path'])) {
    $checkboxAttrs['data-enable'] = Hash::get($row, $field['enable_path']) ? '1' : '0';
}

if (isset($field['require_path'])) {
    $checkboxAttrs['data-require'] = Hash::get($row, $field['require_path']) ? '1' : '0';
}

if (isset($field['highlight_path'])) {
    $checkboxAttrs['data-highlight'] = Hash::get($row, $field['highlight_path']) ? '1' : '0';
}

/*
 * Remote preview rows (server event index) are selectable for a mass fetch, but
 * their id belongs to the remote instance — the ACL branches below would answer
 * about whatever local record happens to share that id. Nothing local to delete
 * either, so the delete-gated buttons stay hidden.
 */
$isRemoteRow = !empty($field['remote']);
if ($isRemoteRow) {
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = '0';
}

if (!$isRemoteRow && $field['data_path'] === 'Event.id') {
    $mayModify = $this->Acl->canModifyEvent($row);
    $canPublish = $this->Acl->canPublishEvent($row);
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Attribute.id') {
    if (!isset($mayModify)){
        $mayModify = $this->Acl->canModifyEvent($row);
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Collection.id' || !empty($data['Collection'])) {
    if (!isset($mayModify)){
        $mayModify = $this->Acl->canModifyCollection($row);
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'EventReport.id') {
    if (!isset($mayModify)) {
        $mayModify = $isSiteAdmin || !empty($me['Role']['perm_add']);
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'EventReportTemplateVariable.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}


if ($field['data_path'] === 'Warninglist.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Galaxy.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'GalaxyElement.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin || !empty($me['Role']['perm_galaxy_editor']);
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'GalaxyCluster.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin || !empty($me['Role']['perm_galaxy_editor']);
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Noticelist.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Regexp.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Allowedlist.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'CorrelationExclusion.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'EventBlocklist.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin || !empty($me['Role']['perm_add']);
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'OrgBlocklist.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'GalaxyClusterBlocklist.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin || !empty($me['Role']['perm_galaxy_editor']);
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'SightingBlocklist.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'AnalystDataBlocklist.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'News.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Bookmark.id') {
    if (!isset($mayModify)){
        // Mirror Bookmark::mayModify — owner, org admin over own org, or site admin.
        $mayModify = $isSiteAdmin
            || ($me['id'] == $row['Bookmark']['user_id'])
            || (!empty($me['Role']['perm_admin']) && $me['org_id'] == $row['Bookmark']['org_id']);
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Workflow.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'WorkflowBlueprint.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Tag.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'TagCollection.id') {
    if (!isset($mayModify)){
        $mayModify = $mayModify = $this->Acl->canModifyTagCollection($row);
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Taxonomy.id') {
    if (!isset($mayModify)){
        $mayModify = $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Template.id') {
    if (!isset($mayModify)){
        $mayModify = $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'EventTemplate.id') {
    if (!isset($mayModify)) {
        $mayModify = !empty($isSiteAdmin) || (
            !empty($me['Role']['perm_template'])
            && (int)($row['EventTemplate']['org_id'] ?? 0) === (int)$me['org_id']
        );
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'ObjectTemplate.id') {
    if (!isset($mayModify)){
        $mayModify = $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Sightingdb.id') {
    if (!isset($mayModify)){
        $mayModify = $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'TaxiiServer.id') {
    if (!isset($mayModify)){
        $mayModify = $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Cerebrate.id') {
    if (!isset($mayModify)){
        $mayModify = $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'SharingGroup.id') {
    if (!isset($mayModify)){
        $mayModify = $row['editable'];
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($row['deletable']) ? '1' : '0';
}

if ($field['data_path'] === 'SharingGroupBlueprint.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Event.uuid') {
    // Remote preview rows (feed manifest): selectable for a mass fetch, but
    // there is nothing local to delete, so the delete-gated buttons stay hidden.
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = '0';
}

if ($field['data_path'] === 'Feed.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Server.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Organisation.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'AuthKey.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin || !empty($canCreateAuthkey);
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Role.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Task.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'UserSetting.id') {
    // Deletability is resolved server-side (checkAccess + checkSettingAccess)
    // and exposed as UserSetting._canDelete by UserSettingsController::index.
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = !empty($row['UserSetting']['_canDelete']) ? '1' : '0';
}

if ($field['data_path'] === 'Job.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'Inbox.id') {
    if (!isset($mayModify)){
        $mayModify = $isSiteAdmin ?? false;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if ($field['data_path'] === 'DecayingModel.id') {
    // Mirror DecayingModel::isEditableByCurrentUser(); default models can never
    // be deleted (only site-admins may toggle them).
    $dm = $row['DecayingModel'];
    $editable = !empty($isSiteAdmin) || (
        !empty($me['Role']['perm_decaying']) &&
        empty($dm['default']) &&
        $dm['org_id'] == $me['org_id']
    );
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($editable && empty($dm['default'])) ? '1' : '0';
}

if ($field['data_path'] === 'id') {
    if (!isset($mayModify)){
        $mayModify = $mayModify = $isSiteAdmin;
    }
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = ($mayModify) ? '1' : '0';
}

if (in_array($field['data_path'], ['Note.id', 'Opinion.id', 'Relationship.id'], true)) {
    $mdl = strtok($field['data_path'], '.');
    $checkboxAttrs['data-item-id'] = $id;
    $checkboxAttrs['data-can-delete'] = !empty($row[$mdl]['_canEdit']) ? '1' : '0';
}

if ($field['data_path'] === 'existing_tag.Tag.id') {
    $checkboxAttrs['disabled'] = true;
}
?>

<div class="d-inline-flex align-items-center checkbox-actions-wrapper checkbox-index">
    <?= $this->Form->checkbox('selected_items[]', $checkboxAttrs); ?>
</div>
