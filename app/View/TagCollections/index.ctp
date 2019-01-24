<?php
    echo $this->element('generic_table', array(
        'items' => $list,
        'controller' => 'tag_collections',
        'headers' => array(
            'id' => array('sort' => 1),
            'uuid' => array('sort' => 1),
            'name' => array('sort' => 1),
            'tags' => array(),
            'galaxies' => array(),
            'all_orgs' => array(),
            'org_id' => array('alias' => 'Organisation'),
            'user_id' => array('alias' => 'User'),
            'description' => array(),
            'Actions' => array()
        ),
        'row_path' => 'TagCollections/index_row'
    ));

    echo $this->element('side_menu', array('menuList' => 'tag-collections', 'menuItem' => 'index'));
?>
<script type="text/javascript">
    $(document).ready(function() {
        $('.addGalaxy').click(function() {
            addGalaxyListener(this);
        });
    });
</script>
