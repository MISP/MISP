<div class="organisations view">
<div class="row-fluid">
    <div class="span10"><h2><?php  echo __('Organisation ') . h($org['Organisation']['name']);?></h2></div>
    <div class="span2"><div style="float:right;"><?php echo $this->OrgImg->getOrgImg(array('name' => $org['Organisation']['name'], 'id' => $org['Organisation']['id'], 'size' => 48)); ?></div></div>
</div>
<div>
    <dl style="width:600px;">
        <dt><?php echo __('Id'); ?></dt>
        <dd><?php echo h($org['Organisation']['id']); ?>&nbsp;</dd>
        <dt><?php echo 'Organisation name'; ?></dt>
        <dd><?php echo h($org['Organisation']['name']); ?>&nbsp;</dd>
        <dt><?php echo __('Local or remote'); ?></dt>
        <?php
            echo sprintf(
                '<dd><span class="%s bold">%s</span></dd>',
                $org['Organisation']['local'] ? 'green' : 'red',
                $org['Organisation']['local'] ? __('Local') : __('Remote')
            );
        ?>
        <dt><?php echo __('Description'); ?></dt>
        <dd><?php echo h($org['Organisation']['description']); ?>&nbsp;</dd>
        <?php
            if (!empty($org['Organisation']['restricted_to_domain'])) {
                $domains = $org['Organisation']['restricted_to_domain'];
                foreach ($domains as $k => $domain) {
                    $domains[$k] = h($domain);
                }
                $domains = implode("<br />", $domains);
                echo sprintf(
                    '<dt>%s</dt><dd>%s</dd>',
                    __('E-mail domain restrictions'),
                    $domains
                );
            }
        ?>
        <dt><?php echo __('UUID'); ?></dt>
        <dd><?php echo !empty(trim($org['Organisation']['uuid'])) ? h($org['Organisation']['uuid']) : "&nbsp;"; ?></dd>
        <?php if ($isSiteAdmin): ?>
            <dt><?php echo __('Created by'); ?></dt>
            <dd><?php echo isset($org['Organisation']['created_by_email']) ? h($org['Organisation']['created_by_email']) : __("Unknown"); ?></dd>
            <dt><?php echo __('Creation time'); ?></dt>
            <dd><?php echo h($org['Organisation']['date_created']); ?></dd>
            <dt><?php echo __('Last modified'); ?></dt>
            <dd><?php echo h($org['Organisation']['date_modified']); ?></dd>
        <?php endif;?>
        <?php
            $optionalFields = array('sector' => 'Sector', 'nationality' => 'Nationality', 'type' => 'Organisation type', 'contacts' => 'Contact information');
            foreach ($optionalFields as $k => $field):
                if (!empty(trim($org['Organisation'][$k]))):
        ?>
                    <dt><?php echo $field; ?></dt>
                    <dd><?php echo trim(h($org['Organisation'][$k])); ?></dd>
        <?php
                endif;
            endforeach;
        ?>
    </dl>
</div>
    <br />
    <?php if ($local): ?>
        <button id="button_description" class="btn btn-inverse toggle-left qet orgViewButton" onClick="organisationViewContent('description', '<?php echo $id;?>');"><?php echo __('Description');?></button>
        <button id="button_description_active" style="display:none;" class="btn btn-primary toggle-left qet orgViewButtonActive" onClick="organisationViewContent('description', '<?php echo $id;?>');"><?php echo __('Description');?></button>

        <?php if ($fullAccess): ?>
            <button id="button_members" class="btn btn-inverse toggle qet orgViewButton" onClick="organisationViewContent('members', '<?php echo $id;?>');"><?php echo __('Members');?></button>
            <button id="button_members_active" style="display:none;" class="btn btn-primary toggle qet orgViewButtonActive" onClick="organisationViewContent('members', '<?php echo $id;?>');"><?php echo __('Members');?></button>
        <?php endif; ?>

        <button id="button_events" class="btn btn-inverse toggle-right qet orgViewButton" onClick="organisationViewContent('events', '<?php echo $id;?>');"><?php echo __('Events');?></button>
        <button id="button_events_active" style="display:none;" class="btn btn-primary toggle-right qet orgViewButtonActive" onClick="organisationViewContent('events', '<?php echo $id;?>');"><?php echo __('Events');?></button>
    <br /><br />
    <?php endif;?>
    <div id="ajaxContent" style="width:100%;"></div>
</div>
<?php
    if ($isSiteAdmin) echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'viewOrg'));
    else echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'viewOrg'));
?>
<script type="text/javascript">
    <?php
        $startingTab = 'description';
        if (!$local) $startingTab = 'events';
    ?>
    $(document).ready(function () {
        organisationViewContent('<?php echo $startingTab; ?>', '<?php echo h($id);?>');
    });
</script>
