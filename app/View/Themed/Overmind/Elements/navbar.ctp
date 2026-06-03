<nav class="navbar navbar-expand-xl navbar-dark fixed-top shadow-sm" style="background-color: #28191B;">
    <div class="container-fluid">
        <a class="navbar-brand fw-bold" href="<?= empty($homepage['path']) ? $baseurl .'/' : $baseurl . h($homepage['path']) ?>">
            <?= $this->Html->image('misp-logo-main-cmyk-icon coul.png', ['alt' => __('MISP Logo'), 'class' => 'navbar-logo']) ?>
        </a>

        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#mainNavbar">
            <span class="navbar-toggler-icon"></span>
        </button>

        <div class="collapse navbar-collapse justify-content-between" id="mainNavbar">
            <ul class="navbar-nav mb-lg-0">
                <?php foreach ($menus['left'] as $item): ?>
                    <?= $this->element('navbar_nav', ['item' => $item]) ?>
                <?php endforeach; ?>
            </ul>

            <ul class="navbar-nav mb-lg-0">
                <?php foreach ($menus['right'] as $item): ?>
                    <?= $this->element('navbar_nav', ['item' => $item, 'alignEnd' => true]) ?>
                <?php endforeach; ?>
            </ul>
        </div>
    </div>
</nav>
 

<script>
    document.addEventListener('DOMContentLoaded', function() {
        const themeButtons = document.querySelectorAll('.setTheme');

        themeButtons.forEach(function(button) {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();

                const theme = String(this.dataset.theme || '');
                const safeTheme = encodeURIComponent(theme);

                fetch('<?php echo $baseurl; ?>/user_settings/setTheme/' + safeTheme, {
                    method: 'POST',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                })
                .then(response => {
                    if (response.ok) {
                        location.reload();
                        throw new ShowToast('<?php echo __('Theme updated!'); ?>');
                    } else {
                        throw new Error('Server Error');
                    }
                })
                .catch(error => {
                    alert('<?php echo __('Failed to toggle Beta UI. Please try again.'); ?>');
                });
            });
        });

        document.querySelectorAll('.toggle-dark-mode').forEach(function(button) {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                toggleDarkMode();
            });
        });

        document.querySelectorAll('.set-homepage').forEach(function(button) {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();

                fetch('<?php echo $baseurl; ?>/user_settings/setHomePage', {
                    method: 'POST',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest',
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ path: window.location.pathname })
                })
                .then(response => {
                    if (!response.ok) throw new Error('Server Error');
                    showToast('<?php echo __('Homepage saved!'); ?>');
                })
                .catch(() => {
                    showToast('<?php echo __('Failed to set homepage. Please try again.'); ?>', 'danger');
                });
            });
        });
    });
</script>