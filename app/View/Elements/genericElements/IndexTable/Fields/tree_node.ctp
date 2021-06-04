<?php
/**
 * Tree node used by the tree generic element
 * @param array $nodeDataPaths Different datapath that can be used to further extract more data or to be passed to other elements
 *    array(
 *      'main_data_path' => <string>,   *required*  Array of data to be drawn for this level
 *      'node_link_path' => <string>,   *optional*  The data to be used for displayed the link
 *      'node_link_title' => <string>,  *optional*  The title to be used for the link if node_link_path provided, otherwise the verbatim value to be displayed
 *    )
 * @param array $data The data to be used to draw the node
 * @param int   $level The current node depth in the tree
 */
?>
<?php if (!empty($data)): ?>
    <?php
        if (!isset($data[0])) {
            $data = array($data);
        }
        $level = isset($level) ? $level : 0;
        $offsetLeft = $level * 15;
    ?>
        <?php foreach ($data as $item): ?>
            <?php
                $linkTitle = Hash::extract($item, $datapath['node_link_title']);
                if (!empty($linkTitle)) {
                    $linkTitle = $linkTitle[0];
                }
            ?>
            <div class="extendedByCell" style="margin-left: <?= $offsetLeft ?>px">
                <span class="<?= $level > 0 ? 'apply_css_arrow' : '' ?>">
                    <?php if ($level > 0): ?>
                        <i class="<?php echo $this->FontAwesome->findNamespace('code-branch'); ?> fa-code-branch fa-rotate-180 fa-flip-vertical"></i>
                    <?php endif; ?>
                    <span style="margin-left: 0.2em;">
                        <?php 
                            if (isset($datapath['node_link_path'])) {
                                echo $this->element('genericElements/IndexTable/Fields/links', array(
                                    'row' => $item,
                                    'field' => array(
                                        'url' => $baseurl . '/galaxy_clusters/view/%s',
                                        'data_path' => $datapath['node_link_path'],
                                        'title' => $linkTitle
                                    ),
                                ));
                            } else {
                                echo sprintf('<strong style="font-size: larger;">%s</strong>', h($linkTitle));
                            }
                        ?>
                    </span>
                </span>
            </div>
        <?php endforeach; ?>
<?php endif; ?>
