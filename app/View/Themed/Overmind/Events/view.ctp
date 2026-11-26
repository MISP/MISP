<?php
    $this->set('headerTitle', 'Color Palette Test');
    $this->set('headerDescription', 'Bootstrap theme color preview');
    $this->set('headerActions', []);
?>

<div class="container-fluid py-4">

    <h5 class="mb-3 text-muted">Theme Colors</h5>
    <div class="d-flex flex-wrap gap-2 mb-5">
        <button class="btn btn-primary">primary</button>
        <button class="btn btn-secondary">secondary</button>
        <button class="btn btn-success">success</button>
        <button class="btn btn-info">info</button>
        <button class="btn btn-warning">warning</button>
        <button class="btn btn-danger">danger</button>
        <button class="btn btn-light">light</button>
        <button class="btn btn-dark">dark</button>
    </div>

    <h5 class="mb-3 text-muted">Outline Variants</h5>
    <div class="d-flex flex-wrap gap-2 mb-5">
        <button class="btn btn-outline-primary">primary</button>
        <button class="btn btn-outline-secondary">secondary</button>
        <button class="btn btn-outline-success">success</button>
        <button class="btn btn-outline-info">info</button>
        <button class="btn btn-outline-warning">warning</button>
        <button class="btn btn-outline-danger">danger</button>
        <button class="btn btn-outline-light">light</button>
        <button class="btn btn-outline-dark">dark</button>
    </div>

    <h5 class="mb-3 text-muted">Custom Colors</h5>
    <div class="d-flex flex-wrap gap-2 mb-5">
        <button class="btn btn-event">event</button>
        <button class="btn btn-object">object</button>
        <button class="btn btn-attribute">attribute</button>
        <button class="btn btn-tag">tag</button>
        <button class="btn btn-galaxy">galaxy</button>
        <button class="btn btn-report">report</button>
        <button class="btn btn-sighting">sighting</button>
        <button class="btn btn-correlation">correlation</button>
    </div>

    <h5 class="mb-3 text-muted">Custom Outline Variants</h5>
    <div class="d-flex flex-wrap gap-2 mb-5">
        <button class="btn btn-outline-event">event</button>
        <button class="btn btn-outline-object">object</button>
        <button class="btn btn-outline-attribute">attribute</button>
        <button class="btn btn-outline-tag">tag</button>
        <button class="btn btn-outline-galaxy">galaxy</button>
        <button class="btn btn-outline-report">report</button>
        <button class="btn btn-outline-sighting">sighting</button>
        <button class="btn btn-outline-correlation">correlation</button>
    </div>

    <h5 class="mb-3 text-muted">Badges</h5>
    <div class="d-flex flex-wrap gap-2 mb-5">
        <span class="badge bg-primary">primary</span>
        <span class="badge bg-secondary">secondary</span>
        <span class="badge bg-success">success</span>
        <span class="badge bg-info text-dark">info</span>
        <span class="badge bg-warning text-dark">warning</span>
        <span class="badge bg-danger">danger</span>
        <span class="badge bg-light text-dark">light</span>
        <span class="badge bg-dark">dark</span>
        <span class="badge bg-event">event</span>
        <span class="badge bg-object">object</span>
        <span class="badge bg-attribute">attribute</span>
        <span class="badge bg-tag">tag</span>
        <span class="badge bg-galaxy">galaxy</span>
    </div>

    <h5 class="mb-3 text-muted">Alerts</h5>
    <div class="d-flex flex-column gap-2">
        <div class="alert alert-primary mb-0">primary</div>
        <div class="alert alert-secondary mb-0">secondary</div>
        <div class="alert alert-success mb-0">success</div>
        <div class="alert alert-info mb-0">info</div>
        <div class="alert alert-warning mb-0">warning</div>
        <div class="alert alert-danger mb-0">danger</div>
    </div>

</div>
