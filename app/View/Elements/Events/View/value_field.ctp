<?php
$truncateLongText = function ($text, $maxLength = 500, $maxLines = 10) {
    $truncated = false;
    if (mb_strlen($text) > $maxLength) {
        $text = mb_substr($text, 0, 500);
        $truncated = true;
    }

    if (substr_count($text, "\n") > $maxLines) {
        $lines = explode("\n", $text);
        $text = implode("\n", array_slice($lines, 0, $maxLines));
        $truncated = true;
    }

    if ($truncated) {
        return $text;
    }
    return null;
};

if (!isset($linkClass)) {
    $linkClass = null;
}

switch ($object['type']) {
    case 'attachment':
    case 'malware-sample':
        if ($object['type'] === 'attachment' && isset($object['image'])) {
            if ($object['image'] === true) {
                $img = '<it class="fa fa-spin fa-spinner" style="font-size: large; left: 50%; top: 50%;"></it>';
                $img .= '<img class="screenshot screenshot-collapsed useCursorPointer img-rounded hidden" src="' . $baseurl . sprintf('/%s/viewPicture/', $object['objectType'] == 'proposal' ? 'shadowAttributes' : 'attributes') . h($object['id']) . '/1' . '" title="' . h($object['value']) . '" onload="$(this).show(200); $(this).parent().find(\'.fa-spinner\').remove();"/>';
                echo $img;
            } else {
                $extension = pathinfo($object['value'], PATHINFO_EXTENSION);
                $uri = 'data:image/' . strtolower(h($extension)) . ';base64,' . h($object['image']);
                echo '<img class="screenshot screenshot-collapsed useCursorPointer" src="' . $uri . '" title="' . h($object['value']) . '" />';
            }
        } else {
            $filenameHash = explode('|', h($object['value']));
            if (strrpos($filenameHash[0], '\\')) {
                $filepath = substr($filenameHash[0], 0, strrpos($filenameHash[0], '\\'));
                $filename = substr($filenameHash[0], strrpos($filenameHash[0], '\\'));
                echo h($filepath);
            } else {
                $filename = $filenameHash[0];
            }

            if (isset($object['objectType'])) {
                if (array_key_exists('infected', $object) && $object['infected'] !== false) { // it is not possible to use isset
                    if ($object['infected'] === null) {
                        $confirm = __('This file was not checked by AV scan. Do you really want to download it?');
                    } else {
                        $confirm = __('According to AV scan, this file contains %s malware. Do you really want to download it?', $object['infected']);
                    }
                } else {
                    $confirm = null;
                }

                $controller = $object['objectType'] === 'proposal' ? 'shadow_attributes' : 'attributes';
                $url = array('controller' => $controller, 'action' => 'download', $object['id']);
                echo $this->Html->link($filename, $url, array('class' => $linkClass), $confirm);
            } else {
                echo $filename;
            }
            if (isset($filenameHash[1])) {
                echo '<br>' . $filenameHash[1];
            }
            if (isset($object['infected']) && $object['infected'] !== false) {
                echo ' <i class="fas fa-virus" title="' . __('This file contains malware %s', $object['infected'])  . '"></i>';
            }
        }
        break;
    case 'datetime':
        echo $this->Time->time($object['value']);
        break;

    case 'vulnerability':
        $cveUrl = Configure::read('MISP.cveurl') ?: 'https://cve.circl.lu/cve/';
        echo $this->Html->link($object['value'], $cveUrl . $object['value'], [
            'target' => '_blank',
            'class' => $linkClass,
            'rel' => 'noreferrer noopener',
            'title' => __('Show more information about this vulnerability in external tool'),
        ]);
        break;

    case 'weakness':
        $cweUrl = Configure::read('MISP.cweurl') ?: 'https://cve.circl.lu/cwe/';
        $link = $cweUrl . explode("-", $object['value'])[1];
        echo $this->Html->link($object['value'], $link, [
            'target' => '_blank',
            'class' => $linkClass,
            'rel' => 'noreferrer noopener',
            'title' => __('Show more information about this weakness in external tool'),
        ]);
        break;

    case 'link':
        echo $this->Html->link($object['value'], $object['value'], ['class' => $linkClass, 'rel' => 'noreferrer noopener']);
        break;

    case 'cortex':
        echo '<span data-full="' . h($object['value']) . '" data-full-type="cortex"><a href="#">' . __('Cortex object') . '</a></span>';
        break;

    case 'text':
        if (in_array($object['category'], array('External analysis', 'Internal reference')) && Validation::uuid($object['value'])) {
            $url = array('controller' => 'events', 'action' => 'view', $object['value']);
            echo $this->Html->link($object['value'], $url, array('class' => $linkClass));
        } else {
            $value = str_replace("\r", '', $object['value']);
            $truncated = $truncateLongText($value);
            if ($truncated) {
                echo '<span style="white-space: pre-wrap;" data-full="' . h($object['value']) .'" data-full-type="text">' .
                    str_replace(" ", '&nbsp;', h(rtrim($truncated)));
                echo ' <b>&hellip;</b><br><a href="#">' . __('Show all') . '</a></span>';
            } else {
                echo '<span style="white-space: pre-wrap;">' . str_replace(" ", '&nbsp;', h($value)) . '</span>';
            }
        }
        break;

    case 'hex':
        echo '<span class="hex-value" title="' . __('Hexadecimal representation') . '">' . h($object['value']) . '</span>&nbsp;';
        echo '<span role="button" tabindex="0" aria-label="' . __('Switch to binary representation') . '" class="fas fa-redo hex-value-convert useCursorPointer" title="' . __('Switch to binary representation') . '"></span>';
        break;

    case 'ip-dst|port':
    case 'ip-src|port':
    case 'hostname|port':
        $valuePieces = explode('|', $object['value']);
        if (substr_count($valuePieces[0], ':') >= 2) {
            echo '[' . h($valuePieces[0]) . ']:' . h($valuePieces[1]); // IPv6 style
        } else {
            echo h($valuePieces[0]) . ':' . h($valuePieces[1]);
        }
        break;

    /** @noinspection PhpMissingBreakStatementInspection */
    case 'domain':
        if (strpos($object['value'], 'xn--') !== false && function_exists('idn_to_utf8')) {
            echo '<span title="' . h(idn_to_utf8($object['value'])) . '">' . h($object['value']) . '</span>';
            break;
        }

    default:
        if (strpos($object['type'], '|') !== false) {
            $valuePieces = explode('|', $object['value']);
            foreach ($valuePieces as $k => $v) {
                $valuePieces[$k] = h($v);
            }
            echo implode('<br>', $valuePieces);
        } else {
            $value = str_replace("\r", '', $object['value']);
            $truncated = $truncateLongText($value);
            if ($truncated) {
                $rawTypes = ['email-header', 'yara', 'pgp-private-key', 'pgp-public-key', 'url'];
                $dataFullType = in_array($object['type'], $rawTypes) ? 'raw' : 'text';
                echo '<span style="white-space: pre-wrap;" data-full="' . h($value) .'" data-full-type="' . $dataFullType .'">' . h($truncated) .
                    ' <b>&hellip;</b><br><a href="#">' . __('Show all') . '</a></span>';
            } else {
                echo '<span style="white-space: pre-wrap;">' . h($value) . '</span>';
            }
        }
}

if (isset($object['validationIssue'])) {
    echo ' <span class="fa fa-exclamation-triangle" title="' . __('Warning, this doesn\'t seem to be a legitimate %s value', strtoupper(h($object['type']))) . '">&nbsp;</span>';
}

if (isset($object['warnings'])) {
    $temp = '';
    foreach ($object['warnings'] as $warning) {
        $temp .= '<span class="bold">' . h($warning['match']) . ':</span> <span class="red">' . h($warning['warninglist_name']) . '</span><br>';
    }
    echo ' <span aria-label="' . __('warning') . '" role="img" tabindex="0" class="fa fa-exclamation-triangle" data-placement="right" data-toggle="popover" data-content="' . h($temp) . '" data-trigger="hover">&nbsp;</span>';
}
