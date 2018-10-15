<?php
    $feedTemplate = array(
        'id', 'name', 'provider', 'url'
    );
?>
<div class="feed index">
    <h2><?php echo __('Feed overlap analysis matrix');?></h2>
    <?php
        if (count($feeds) >= 2):
    ?>
        <div>
            <table class="table table-striped table-hover table-condensed" style="width:100px;">
                <tr>
                        <th>&nbsp;</th>
                    <?php
                    foreach ($feeds as $item):
                            $popover = '';
                            foreach ($feedTemplate as $element):
                                $popover .= '<span class=\'bold\'>' . Inflector::humanize($element) . '</span>: <span class=\'bold blue\'>' . h($item['Feed'][$element]) . '</span><br />';
                            endforeach;
                  ?>
                    <th>
                            <div data-toggle="popover" data-content="<?php echo $popover; ?>" data-trigger="hover">
                            <?php echo h($item['Feed']['id']); ?>
                            </div>
                    </th>
                  <?php
                    endforeach;
                  ?>
                </tr>
              <?php
                foreach ($feeds as $item):
                        $popover = '';
                        foreach ($feedTemplate as $element):
                            $popover .= '<span class=\'bold\'>' . Inflector::humanize($element) . '</span>: <span class=\'bold blue\'>' . h($item['Feed'][$element]) . '</span><br />';
                        endforeach;
              ?>
                <tr>
                    <td class="short">
                            <div data-toggle="popover" data-content="<?php echo $popover;?>" data-trigger="hover">
                                <?php echo h($item['Feed']['id']) . ' ' . h($item['Feed']['name']); ?>&nbsp;
                            </div>
                        </td>
                        <?php
                        foreach ($feeds as $item2):
                                    $percentage = -1;
                                    $class = 'bold';
                                    foreach ($item['Feed']['ComparedFeed'] as $k => $v):
                                        if ($item2['Feed']['id'] == $v['id']):
                                            $percentage = $v['overlap_percentage'];
                                            if ($percentage <= 5) $class .= ' green';
                                            else if ($percentage <= 50) $class .= ' orange';
                                            else $class .= ' red';
                                            break;
                                        endif;
                                    endforeach;
                                    $title = '';
                                    if ($percentage == 0) $popover = __('None or less than 1% of the data of %s is contained in %s (%s matching values)', $item['Feed']['name'], $item2['Feed']['name'], $v['overlap_count']);
                                    else if ($percentage > 0) $popover = __('%s\% of the data of %s is contained in %s (%s matching values)',$percentage, $item['Feed']['name'], $item2['Feed']['name'], $v['overlap_count'])
                            ?>
                                <td class="<?php echo h($class); ?>">
                                    <div data-toggle="popover" data-content="<?php echo h($popover);?>" data-trigger="hover">
                                        <?php echo (($percentage == -1) ? '-' : h($percentage) . '%');?>
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
            echo '<p class="red bold">Not enough feeds cached. Make sure you have at least 2 feeds that are cached and available.</p>';
        endif;
    ?>
</div>
<script type="text/javascript">
    $(document).ready(function(){
        popoverStartup();
    });
</script>
<?php
    echo $this->element('side_menu', array('menuList' => 'feeds', 'menuItem' => 'compare'));
?>
