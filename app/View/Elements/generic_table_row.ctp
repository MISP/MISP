<?php
    $title = sprintf('<h2>%s index</h2>', Inflector::humanize($controller));
    if (!empty($description)) {
        $description = sprintf('<p>%s</p>', Inflector::humanize($description));
    } else {
        $description = '';
    }
    $pagination = sprintf(
        '<div class="pagination"><ul>%s%s%s</ul></div>',
        $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span')),
        $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span')),
        $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'))
    );
    $table_headers = '';
    foreach ($headers as $header => $data) {
        if (!empty($data['sort'])) {
            if (!empty($data['alias'])) {
                $header_data = $this->Paginator->sort($header, $data['alias']);
            } else {
                $header_data = $this->Paginator->sort($header);
            }
        } else {
            $header_data = '<th>' . h($header) . '</th>';
        }
        $table_headers .= $header_data;
    }
    $table_contents = $this->element($row_path, array(
        'items' => $items
    ));
    $table = sprintf(
        '<table class="table table-striped table-hover table-condensed">%s%s</table>',
        $table_header,
        $table_contents
    );
    $pagination_details = sprintf(
        '<p>%s</p>',
        $this->Paginator->counter(
            array(
                'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
            )
        )
    );
    echo sprintf(
        '<div class="%s index">%s%s%s%s%s%s</div>',
        $controller,
        $title,
        $description,
        $pagination,
        $table,
        $pagination_details,
        $pagination
    );
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'whitelist', 'menuItem' => 'index'));
