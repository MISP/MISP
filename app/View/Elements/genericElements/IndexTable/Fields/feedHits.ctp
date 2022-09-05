<?php
$object = Hash::extract($row, $field['data']['object']['value_path']);

$li = [];
if (isset($object['Feed'])) {
    foreach ($object['Feed'] as $feed) {
        $relatedData = array(
            __('Name') => h($feed['name']),
            __('Provider') => h($feed['provider']),
        );
        if (isset($feed['event_uuids'])) {
            $relatedData[__('Event UUIDs')] = implode('<br>', array_map('h', $feed['event_uuids']));
        }
        $popover = '';
        foreach ($relatedData as $k => $v) {
            $popover .= '<span class="bold black">' . $k . '</span>: <span class="blue">' . $v . '</span><br>';
        }
        if ($isSiteAdmin || $hostOrgUser) {
            if ($feed['source_format'] === 'misp') {
                $liContents = sprintf(
                    '<form action="%s/feeds/previewIndex/%s" method="post" style="margin:0;line-height:auto;">%s%s</form>',
                    $baseurl,
                    h($feed['id']),
                    sprintf(
                        '<input type="hidden" name="data[Feed][eventid]" value="%s">',
                        h(json_encode($feed['event_uuids']))
                    ),
                    sprintf(
                        '<input type="submit" class="linkButton useCursorPointer" value="%s" data-toggle="popover" data-content="%s" data-trigger="hover" style="margin-right:3px;line-height:normal;vertical-align: text-top;">',
                        h($feed['id']),
                        h($popover)
                    )
                );
            } else {
                $liContents = sprintf(
                    '<a href="%s/feeds/previewIndex/%s" data-toggle="popover" data-content="%s" data-trigger="hover">%s</a>',
                    $baseurl,
                    h($feed['id']),
                    h($popover),
                    h($feed['id'])
                );
            }
        } else {
            $liContents = sprintf(
                '<span>%s</span>',
                h($feed['id'])
            );
        }
        $li[] = "<li>$liContents</li>";
    }
}
if (isset($object['Server'])) {
    foreach ($object['Server'] as $server) {
        $popover = '';
        foreach ($server as $k => $v) {
            if ($k === 'id') continue;
            if (is_array($v)) {
                $v = array_map('h', $v);
                $v = implode('<br>', $v);
            } else {
                $v = h($v);
            }
            $popover .= '<span class=\'bold black\'>' . Inflector::humanize(h($k)) . '</span>: <span class="blue">' . $v . '</span><br>';
        }
        foreach ($server['event_uuids'] as $k => $event_uuid) {
            $liContents = '';
            if ($isSiteAdmin) {
                $liContents .= sprintf(
                    '<a href="%s/servers/previewEvent/%s/%s" data-toggle="popover" data-content="%s" data-trigger="hover">%s</a>&nbsp;',
                    $baseurl,
                    h($server['id']),
                    h($event_uuid),
                    h($popover),
                    'S' . h($server['id']) . ':' . ($k + 1)
                );
            } else {
                $liContents .= sprintf(
                    '<span>%s</span>',
                    'S' . h($server['id']) . ':' . ($k + 1)
                );
            }
            $li[] = "<li>$liContents</li>";
        }
    }
}

if (!empty($li)) {
    echo '<ul class="inline">' . implode('', $li) .'</ul>';
}
