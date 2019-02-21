<?php
    /*
     *  This template creates a separator and check for the conditions under which it hsould be displayed.
     */
     if (!isset($data['requirement']) || $data['requirement']) {
         echo sprintf('<li class="divider"></li>');
     }
?>