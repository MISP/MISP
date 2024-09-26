<div class="index">
    <div style="padding: 1em 2em; margin-bottom: 2em;">
        <h1>Exporting cluster into the misp-galaxy format</h1>

        <p>This JSON can be added added to the <code class="quickSelect">misp-galaxy/clusters/<?= h($cluster['GalaxyCluster']['type']) ?>.json</code>.</p>

        <pre class="quickSelect"><?= JsonTool::encode($convertedCluster, true) ?></pre>
    </div>
</div>
<?= $this->element('/genericElements/SideMenu/side_menu', ['menuList' => 'galaxies', 'menuItem' => 'view_cluster']);