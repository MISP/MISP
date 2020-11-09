<?php
/*
 *  This template creates a separator and check for the conditions under which it should be displayed.
 */
 if (!isset($data['requirement']) || $data['requirement']) {
     echo '<li class="divider"></li>';
 }
