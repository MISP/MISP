<?php
$generatePopover = function (array $server) {
    $popover = '';
    foreach (['id' => __('ID'), 'name' => __('Name'), 'url' => __('URL'), 'events_count' => __('Events count')] as $key => $name) {
        $popover .= '<span class=\'bold\'>' . $name . '</span>: <span class=\'bold blue\'>' . h($server['Server'][$key]) . '</span><br>';
    }
    return $popover;
};
?>
<div class="index">
    <h2><?php echo __('Server events overlap analysis matrix');?></h2>
    <?php
        if (count($servers) >= 2):
    ?>
        <div>
            <table class="table table-striped table-hover table-condensed" style="width:100px;">
                <tr>
                    <th></th>
                    <?php
                    foreach ($servers as $server):
                  ?>
                    <th style="text-align: center">
                        <div data-toggle="popover" data-content="<?= $generatePopover($server); ?>" data-trigger="hover">
                            <?= 'S' . h($server['Server']['id']) ?>
                        </div>
                    </th>
                  <?php
                    endforeach;
                  ?>
                </tr>
              <?php
                foreach ($servers as $item):
              ?>
                <tr>
                    <td class="short">
                        <div data-toggle="popover" data-content="<?= $generatePopover($item) ?>" data-trigger="hover">
                            <?= __('<b>S%s</b>: %s', h($item['Server']['id']), h($item['Server']['name'])) ?>
                        </div>
                    </td>
                        <?php
                        foreach ($servers as $item2):
                            $percentage = $count = null;
                            if (isset($overlap[$item['Server']['id']][$item2['Server']['id']])) {
                                $percentage = $overlap[$item['Server']['id']][$item2['Server']['id']]['percentage'];
                                $count = $overlap[$item['Server']['id']][$item2['Server']['id']]['events'];
                            }

                            $class = 'bold';
                            if ($percentage !== null) {
                                if ($percentage <= 5) {
                                    $class .= ' green';
                                } else if ($percentage <= 50) {
                                    $class .= ' orange';
                                } else {
                                    $class .= ' red';
                                }
                            }

                            if ($percentage === null) {
                                $popover = '';
                            } else if ($percentage == 0) {
                                $popover = __('None or less than 1 % of the events of %s is contained in %s (%s matching events)', $item['Server']['name'], $item2['Server']['name'], $count);
                            } else if ($percentage > 0) {
                                $popover = __('%s % of the events of %s is contained in %s (%s matching events)', $percentage, $item['Server']['name'], $item2['Server']['name'], $count);
                            }
                            ?>
                            <td class="<?= $class ?>" style="text-align: center">
                                <div data-toggle="popover" data-content="<?= h($popover) ?>" data-trigger="hover">
                                    <?= $percentage === null ? '&ndash;' : h($percentage) . '&nbsp;%' ?>
                                </div>
                            </td>
                            <?php
                        endforeach;
                      ?>
                </tr>
              <?php
                endforeach;
              ?>
            </table>
        </div>
    <?php
        else:
            echo '<p class="red bold">Not enough remote servers. Make sure you have at least 2 server that are enabled and available.</p>';
        endif;
    ?>
</div>
<script type="text/javascript">
    $(function(){
        popoverStartup();
    });
</script>
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'sync', 'menuItem' => 'compareServers'));
