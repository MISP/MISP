<div>
        <?php
        /*
        * A simple button to add a link to a specific section
        *
        * Expected input:
        * { url: <relative url>, text: <text to be displayed on the button>}
        *
        * Example:
        * {url: "/events/index", text: "To the list of events"}
        *
        */

        $url = $data['url'] ?? '';

        $url = rawurldecode($url);
        $parts = parse_url($url);

        if ($parts === false || isset($parts['host']) || isset($parts['scheme']) || isset($parts['user']) || $parts['path'][0] !== '/') {
            echo sprintf('<button class="btn btn-secondary widget-button">%s</button>', __('Invalid URL'));
        } else {
            $betterUrl = $parts['path']
                . (isset($parts['query']) ? '?' . $parts['query'] : '')
                . (isset($parts['fragment']) ? '#' . $parts['fragment'] : '');

            echo '<a href="' . htmlspecialchars($betterUrl . $url, ENT_QUOTES, 'UTF-8') . '">';
            echo '<button class="btn btn-primary widget-button">';
            echo h($data['text']);
            echo '</button></a>';
        }
        ?>
</div>

<style widget-scoped>
    .widget-button {
        height: 100%;
        width: 100%;
        text-align: center;
        font-size: large;
    }
</style>