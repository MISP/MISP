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
if (!isset($imgStyle)) $imgStyle = array('style' => 'float:right');
else $imgStyle = '';
$imgRelativePath = 'orgs/' . $imgId . '.png';
$imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . $imgRelativePath;
$imgExtraOptions = $imgStyle;
if (file_exists($imgAbsolutePath)) {
	echo $this->Html->image($imgRelativePath, Set::merge(array('alt' => $imgId, 'style' => 'width:' . $imgSize . 'px; height:' . $imgSize . 'px', 'title' => $imgId), $imgExtraOptions));
} else {
	echo $this->Html->tag('span', $imgId, Set::merge(array('class' => 'img'), $imgExtraOptions));
}