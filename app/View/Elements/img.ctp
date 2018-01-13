<?php

/**
 * Display an image or just the $imgId if no file exists.
 *
 * @param id, an image identifying string
 *
 * used in Events/index.ctp
 * used in Events/view.ctp
 */

$imgId = h($id);
if (!isset($imgSize)) $imgSize = 48;
if (!isset($imgStyle)) {
	$imgStyle = 'float:right;';
} else if (is_array($imgStyle)) {
	$imgStyle = $imgStyle['style'];
}
else $imgStyle = '';
$imgRelativePath = 'orgs/' . $imgId . '.png';
$imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . $imgRelativePath;
if (file_exists($imgAbsolutePath)) {
	echo $this->Html->image($imgRelativePath, array('alt' => $imgId, 'style' => 'width:' . $imgSize . '; max-height:' . $imgSize . ';' . $imgStyle, 'title' => $imgId));
}
