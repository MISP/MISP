<?php
// Overmind events index: the creator user's email (site admins only).
$email = $row['User']['email'] ?? '';
printf('<span class="te-quiet" title="%s">%s</span>', h($email), h($email));
