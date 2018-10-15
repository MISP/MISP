<div class="taxonomies index">
    <h2><?php echo __('Noticelists');?></h2>
    <div class="pagination">
        <ul>
        <?php
        $this->Paginator->options(array(
            'update' => '.span12',
            'evalScripts' => true,
            'before' => '$(".progress").show()',
            'complete' => '$(".progress").hide()',
        ));

            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        ?>
        </ul>
    </div>
    <div id="hiddenFormDiv">
    <?php
        if ($isSiteAdmin) {
            echo $this->Form->create('Noticelist', array('url' => '/noticelists/toggleEnable'));
            echo $this->Form->input('data', array('label' => false, 'style' => 'display:none;'));
            echo $this->Form->end();
        }
    ?>
    </div>
    <table class="table table-striped table-hover table-condensed">
        <tr>
                <th><?php echo $this->Paginator->sort('id'); ?></th>
                <th><?php echo $this->Paginator->sort('name'); ?></th>
                <th><?php echo $this->Paginator->sort('expanded_name'); ?></th>
                <th><?php echo __('ref');?></th>
                <th><?php echo __('geographical_area');?></th>
                <th><?php echo __('version');?></th>
                <th><?php echo __('enabled');?></th>
                <th class="actions"><?php echo __('Actions');?></th>
        </tr>
        <?php
            foreach ($noticelists as $k => $item) {
                echo '<tr>';
                echo sprintf('<td ondblclick="document.location.href =%s">%s&nbsp;</td>', $baseurl . "/noticeists/view/" . h($item['Noticelist']['id']), h($item['Noticelist']['id']));
                echo sprintf('<td ondblclick="document.location.href =%s">%s&nbsp;</td>', $baseurl . "/noticeists/view/" . h($item['Noticelist']['id']), h($item['Noticelist']['name']));
                echo sprintf('<td ondblclick="document.location.href =%s">%s&nbsp;</td>', $baseurl . "/noticeists/view/" . h($item['Noticelist']['id']), h($item['Noticelist']['expanded_name']));
                $references = array();
                foreach ($item['Noticelist']['ref'] as $ref) {
                    $references[] = sprintf('<a href="%s">%s</a>', h($ref), h($ref));
                }
                $references = implode(PHP_EOL, $references);
                echo sprintf('<td ondblclick="document.location.href =%s">%s&nbsp;</td>', $baseurl . "/noticeists/view/" . h($item['Noticelist']['id']), $references);
                $geo = array();
                foreach ($item['Noticelist']['geographical_area'] as $geo_area) {
                    $geo[] = h($geo_area);
                }
                $geo = implode(PHP_EOL, $geo);
                echo sprintf('<td class="short" ondblclick="document.location.href =%s">%s&nbsp;</td>', $baseurl . "/noticeists/view/" . h($item['Noticelist']['id']), $geo);
                echo sprintf('<td class="short" ondblclick="document.location.href =%s">%s&nbsp;</td>', $baseurl . "/noticeists/view/" . h($item['Noticelist']['id']), h($item['Noticelist']['version']));
                if ($isSiteAdmin) {
                    $onClick = 'onClick="toggleSetting(event, \'noticelist_enable\', \'' . h($item['Noticelist']['id']) . '\'); ' . '"';
                } else {
                    $onClick = 'disabled';
                }
                $input = '<input id="checkBox_' . h($item['Noticelist']['id']) . '" type="checkbox" ' . $onClick . ' ' . ($item['Noticelist']['enabled'] ? 'checked' : '') . ' />';
                echo '<td class="short" id="checkbox_row_' . h($item['Noticelist']['id']) . '">' . $input . '</td>';
                $actions = '';
                $actions .= '<a href="' . $baseurl . "/noticelists/view/" . h($item['Noticelist']['id']) . '" class="icon-list-alt" title="' . __('View') . '"></a>';
                echo '<td class="short action-links">' . $actions . '</td>';
                echo '</tr>';

            }
        ?>
    </table>
    <p>
        <?php
        echo $this->Paginator->counter(array(
            'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
        ));
        ?>
    </p>
    <div class="pagination">
        <ul>
        <?php
            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        ?>
        </ul>
    </div>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'noticelist', 'menuItem' => 'index'));
?>
