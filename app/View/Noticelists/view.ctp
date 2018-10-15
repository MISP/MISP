<div class="noticelist view">
<h2><?php echo h(strtoupper($noticelist['Noticelist']['name'])); ?></h2>
    <?php
        $field_names = array('id', 'name', 'version', 'expanded_name', 'ref', 'geographical_area', 'enabled');
        $fields = array();
        foreach ($field_names as $field_name) {
            if ($field_name == 'ref' || $field_name == 'geographical_area') {
                $value = json_decode($noticelist['Noticelist'][$field_name]);
                foreach ($value as $k => $v) {
                    if ($field_name == 'ref') {
                        $value[$k] = '<a href="' . h($v) . '">' . h($v) . '</a>';
                    } else {
                        $value[$k] = h($v);
                    }
                }
                $value = implode(PHP_EOL, $value);
            } else if ($field_name == 'enabled') {
                $value = $noticelist['Noticelist']['enabled'] ? '<span class="green">Yes</span>&nbsp;&nbsp;' : '<span class="red">No</span>&nbsp;&nbsp;';
                if ($isSiteAdmin) {
                    if ($noticelist['Noticelist']['enabled']) {
                        $value .= $this->Form->postLink('(disable)', array('action' => 'enableNoticelist', h($noticelist['Noticelist']['id'])), array('title' => 'Disable'));
                    } else {
                        $value .= $this->Form->postLink('(enable)', array('action' => 'enableNoticelist', h($noticelist['Noticelist']['id']), 'true') ,array('title' => 'Enable'));
                    }
                }
            } else {
                $value = h($noticelist['Noticelist'][$field_name]);
            }
            $fields[] = sprintf('<dt>%s</dt><dd>%s</dd>', Inflector::humanize($field_name), $value);
        }
        $dl = implode($fields);
        echo sprintf('<dl>%s</dl>', $dl);

    ?>
    <br />
    <h3><?php echo __('Values');?></h3>
    <div>
        <table class="table table-striped table-hover table-condensed">
            <tr>
                    <th><?php echo __('Scope'); ?></th>
                    <th><?php echo __('Field'); ?></th>
                    <th><?php echo __('Value'); ?></th>
                    <th><?php echo __('Tags'); ?></th>
                    <th><?php echo __('Message'); ?></th>
            </tr>
        <?php
            foreach ($noticelist['NoticelistEntry'] as $entry) {
                $tr = array();
                $array_fields = array('scope', 'field', 'value', 'tags');
                foreach ($array_fields as $af) {
                    $tr []= '<td class="short">' . implode('<br />', h($entry['data'][$af])) . '</td>';
                }
                $tr []= '<td>' . h($entry['data']['message']['en']) . '</td>';
                echo sprintf('<tr>%s</tr>', implode('', $tr));
            }
    ?>
    </table>
</div>
</div>
<script type="text/javascript">
    $(document).ready(function(){
        $('input:checkbox').removeAttr('checked');
        $('.mass-select').hide();
        $('.select_taxonomy, .select_all').click(function(){
            taxonomyListAnyCheckBoxesChecked();
        });
    });
</script>
<?php
    echo $this->element('side_menu', array('menuList' => 'noticelist', 'menuItem' => 'view'));
?>
