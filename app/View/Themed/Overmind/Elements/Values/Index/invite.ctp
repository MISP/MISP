<?php
/**
 * The region under the box when it has nothing to say: an empty marker,
 * which `value-index.js` reads to tell an untouched region from one
 * showing an answer.
 *
 * It is an element because the page needs it twice: once in the region,
 * and once in a `<template>` the script clones when the reader clears.
 */
?>
<div class="vi-invite" hidden></div>
