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
    echo $this->element('/genericElements/IndexTable/pagination', array('paginator' => $this->Paginator));
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
            '<tr>%s</tr>',
            $this->element('/genericElements/IndexTable/' . $row_element, array('k' => $k, 'row' => $data_row, 'fields' => $data['fields']))
        );
    }
    echo sprintf(
        '<table class="table table-striped table-hover table-condensed">%s%s</table>',
        $this->element('/genericElements/IndexTable/headers', array('fields' => $data['fields'], 'paginator' => $this->Paginator)),
        $rows
    );
    echo $this->element('/genericElements/IndexTable/pagination_counter', array('paginator' => $this->Paginator));
    echo $this->element('/genericElements/IndexTable/pagination', array('paginator' => $this->Paginator));
?>
