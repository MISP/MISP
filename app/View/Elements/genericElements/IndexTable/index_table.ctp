<?php
    /*
     *  echo $this->element('/genericElements/IndexTable/index_table', array(
     *      'top_bar' => (
     *          // search/filter bar information compliant with ListTopBar
     *      ),
     *      'data' => array(
                // the actual data to be used
     *      ),
     *      'fields' => array(
     *          // field list with information for the paginator, the elements used for the individual cells, etc
     *      ),
     *      'title' => optional title,
     *      'description' => optional description
     *  ));
     *
     */
    if (!empty($data['title'])) {
        echo sprintf('<h2>%s</h2>', h($data['title']));
    }
    if (!empty($data['description'])) {
        echo sprintf('<p>%s</p>', h($data['description']));
    }
    if (!empty($data['html'])) {
        echo sprintf('<p>%s</p>', $data['html']);
    }
    $paginationData = array();
    if (!empty($data['paginationBaseurl'])) {
        $paginationData['paginationBaseurl'] = $data['paginationBaseurl'];
    }
    echo $this->element('/genericElements/IndexTable/pagination', $paginationData);
    if (!empty($data['top_bar'])) {
        echo $this->element('/genericElements/ListTopBar/scaffold', array('data' => $data['top_bar']));
    }
    $rows = '';
    foreach ($data['data'] as $k => $data_row) {
        $row_element = 'row';
        if (!empty($data['row_element'])) {
            $row_element = $data['row_element'];
        }
        $rows .= sprintf(
            '<tr data-row-id="%s">%s</tr>',
            h($k),
            $this->element(
                '/genericElements/IndexTable/' . $row_element,
                array(
                    'k' => $k,
                    'row' => $data_row,
                    'fields' => $data['fields'],
                    'options' => empty($data['options']) ? array() : $data['options'],
                    'actions' => empty($data['actions']) ? array() : $data['actions']
                )
            )
        );
    }
    echo sprintf(
        '<table class="table table-striped table-hover table-condensed">%s%s</table>',
        $this->element('/genericElements/IndexTable/headers', array('fields' => $data['fields'], 'paginator' => $this->Paginator, 'actions' => empty($data['actions']) ? false : true)),
        $rows
    );
    echo $this->element('/genericElements/IndexTable/pagination_counter', $paginationData);
    echo $this->element('/genericElements/IndexTable/pagination', $paginationData);
?>
