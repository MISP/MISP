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
$imgRelativePath = 'orgs' . DS . $imgId . '.png';
$imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . $imgRelativePath;
$imgExtraOptions = array('style' => 'float:right;');

if (file_exists($imgAbsolutePath)) {
	echo $this->Html->image($imgRelativePath, Set::merge(array('alt' => $imgId,'width' => '48', 'hight' => '48'), $imgExtraOptions));
} else {
	echo $this->Html->tag('span', $imgId, Set::merge(array('class' => 'img'), $imgExtraOptions));
}