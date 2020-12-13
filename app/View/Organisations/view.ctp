<div class="organisations view">
    <div class="row-fluid">
    <?php
        $table_data = array();
        $table_data[] = array('key' => __('ID'), 'value' => $org['Organisation']['id']);
        $table_data[] = array(
            'key' => __('UUID'),
            'value_class' => 'quickSelect',
            'value' => isset($org['Organisation']['uuid']) ? $org['Organisation']['uuid'] : '',
        );
        $table_data[] = array('key' => __('Organisation name'), 'value' => $org['Organisation']['name']);
        $table_data[] = array(
            'key' => __('Local or remote'),
            'html' => sprintf(
                '<dd><span class="%s bold">%s</span></dd>',
                $org['Organisation']['local'] ? 'green' : 'red',
                $org['Organisation']['local'] ? __('Local') : __('Remote')
            )
        );
        $table_data[] = array('key' => __('Description'), 'value' => $org['Organisation']['description']);
        if (!empty($org['Organisation']['restricted_to_domain'])) {
            $domains = $org['Organisation']['restricted_to_domain'];
            foreach ($domains as $k => $domain) {
                $domains[$k] = h($domain);
            }
            $domains = implode("<br>", $domains);
            $table_data[] = array('key' => __('Domain restrictions'), 'html' => $domains);
        }
        if ($isSiteAdmin) {
            $table_data[] = array('key' => __('Created by'), 'value' => isset($org['Organisation']['created_by_email']) ? $org['Organisation']['created_by_email'] : __("Unknown"));
            $table_data[] = array('key' => __('Creation time'), 'value' => $org['Organisation']['date_created']);
            $table_data[] = array('key' => __('Last modified'), 'value' => $org['Organisation']['date_modified']);
        }
        if (!empty(trim($org['Organisation']['nationality']))) {
            $html = '';
            if (isset($org['Organisation']['country_code'])) {
                $html .= $this->Icon->countryFlag($org['Organisation']['country_code']) . '&nbsp;';
            }
            $html .= trim(h($org['Organisation']['nationality']));
            $table_data[] = array(
                'key' => __('Nationality'),
                'html' => $html,
            );
        }
        foreach (array('sector' => __('Sector'), 'type' => __('Organisation type'), 'contacts' => __('Contact information')) as $k => $field) {
            if (!empty(trim($org['Organisation'][$k]))) {
                $table_data[] = array('key' => $field, 'html' => nl2br(trim(h($org['Organisation'][$k]))));
            }
        }
        echo sprintf(
            '<div class="span8" style="margin:0px;">%s</div><div class="span4" style="horizontal-align:right;">%s</div>',
            sprintf(
                '<h2>%s</h2>%s',
                __('Organisation ') . h($org['Organisation']['name']),
                $this->element('genericElements/viewMetaTable', array('table_data' => $table_data))
            ),
            sprintf(
                '<div style="float:right;">%s</div>',
                $this->OrgImg->getOrgLogo($org, 48)
            )
        );
    ?>
</div>
    <br />
    <?php if ($local && $fullAccess): ?>
        <button id="button_members" class="btn btn-inverse toggle-left qet orgViewButton" onClick="organisationViewContent('members', '<?php echo $id;?>');"><?php echo __('Members');?></button>
        <button id="button_members_active" style="display:none;" class="btn btn-primary toggle-left qet orgViewButtonActive" onClick="organisationViewContent('members', '<?php echo $id;?>');"><?php echo __('Members');?></button>

        <button id="button_events" class="btn btn-inverse toggle-right qet orgViewButton" onClick="organisationViewContent('events', '<?php echo $id;?>');"><?php echo __('Events');?></button>
        <button id="button_events_active" style="display:none;" class="btn btn-primary toggle-right qet orgViewButtonActive" onClick="organisationViewContent('events', '<?php echo $id;?>');"><?php echo __('Events');?></button>
    <br /><br />
    <?php endif;?>
    <?php
        echo $this->Html->script('vis');
        echo $this->Html->css('vis');
        echo $this->Html->css('distribution-graph');
        echo $this->Html->script('network-distribution-graph');
    ?>
    <div id="ajaxContent" style="width:100%;"></div>
</div>
<?php
    if ($isSiteAdmin) echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'viewOrg'));
    else echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'viewOrg'));
?>
<script type="text/javascript">
    <?php
        $startingTab = ($fullAccess && $local) ? 'members' : 'events';
    ?>
    $(function () {
        organisationViewContent('<?php echo $startingTab; ?>', '<?php echo h($id);?>');
    });
</script>
