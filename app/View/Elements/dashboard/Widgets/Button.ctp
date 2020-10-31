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
        echo '<a href="'.$baseurl.h($data['url']).'">';
        echo '<button class="btn btn-primary widget-button">';
        echo h($data['text']);
        echo '</button></a>';
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