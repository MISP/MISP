<?php
    $href_url = isset($href_url) ? $href_url : $baseurl . '/events';
    $hide = isset($hide) ? $hide : false;
?>
<span class="<?php echo $hide ? 'hidden correlation-expanded-area' : '' ?>">
    <span style="display: inline-block; border: 1px solid #ddd; border-radius: 5px; padding: 3px;">
        <table>
            <tbody>
                <tr>
                    <td rowspan="2" style="border-right: 1px solid #ddd; padding-right: 2px">
                        <?php echo $this->OrgImg->getOrgImg(array('name' => $related['Orgc']['name'], 'id' => $related['Orgc']['id'], 'size' => 24)); ?>
                    </td>
                    <td style="line-height: 14px; padding-left: 2px; white-space: nowrap; text-overflow: ellipsis; overflow: hidden; max-width: 430px;">
                        <a title="<?php echo h($related['info']); ?>" href="<?php echo h($href_url) . '/' . $related['id']?>">
                            <span><?php echo h($related['info']) ?>
                        </a>
                    </td>
                </tr>
                <tr>
                    <td style="line-height: 14px; padding-left: 2px;">
                        <i><?php echo h($related['date']); ?></i></span> (<?php echo h($related['id']) ?>)
                    </td>
                </tr>
            </tbody>
        </table>
    </span>
</span>
