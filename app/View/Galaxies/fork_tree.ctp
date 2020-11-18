<div>
    <h6>
        <a class="" href="<?= sprintf('%s/galaxies/view/%s/context:all', $baseurl, $galaxy_id) ?>">
            <i class="<?php echo $this->FontAwesome->findNamespace('arrow-left'); ?> fa-arrow-left"></i>
            <?= __('Back to galaxy') ?>
        </a>
    </h6>
    <h2><?= sprintf(__('%s galaxy cluster extensions'), h($galaxy['Galaxy']['name'])) ?></h2>
    <svg id="treeSVG" style="width: 100%; height: 100%; min-height: 600px;"></svg>
</div>

<?php
echo $this->element('genericElements/assetLoader', array(
    'js' => array('d3')
));
?>


<script type="text/javascript">
var transparentImg = ' data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAC4jAAAuIwF4pT92AAAAB3RJTUUH5AQVCQsbtQbZ8QAAABl0RVh0Q29tbWVudABDcmVhdGVkIHdpdGggR0lNUFeBDhcAAAC5SURBVGje7dcxCoNAEIXhNyoKnkDvfwtP4QUsrWURJCbrTgrLNIakcOF/MP1+8IZlzN2VcwplHgAAAAAAAAAAAABX4y6ldCtAdfXhHqN83+UxyppGVteysswD4Ckprate86wUgqq+V9V1sraVzDKoUIw6lkX7OOoxDHpOk9K2nZViiX+LXTkp/TiUQvioUHGDCl0C3HmJ7auj3v2cosirQvzEAAAAAAAAAAAAAAAAAAAAAAAAAAD8OW/IQVbE0efUAQAAAABJRU5ErkJggg==';
var data = <?= json_encode($tree) ?>;
var margin = {top: 10, right: 10, bottom: 10, left: 20};
var width, height;
$(document).ready(function () {
    var $tree = $('#treeSVG');
    width = $tree.width() - margin.right - margin.left;
    height = $tree.height() - margin.top - margin.bottom;
    buildTree();
});

function buildTree() {
    data[0].isRoot = true;
    var tree = d3.layout.tree(data)
        .size([height, width]);
    
    var diagonal = function link(d) {
        return "M" + d.source.y + "," + d.source.x
            + "C" + (d.source.y + d.target.y) / 2 + "," + d.source.x
            + " " + (d.source.y + d.target.y) / 2 + "," + d.target.x
            + " " + d.target.y + "," + d.target.x;
    };
    
    var svg = d3.select("#treeSVG")
        .attr("width", width + margin.right + margin.left)
        .attr("height", height + margin.top + margin.bottom)
        .append("g")
            .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

    var root = data[0];
    root.x0 = height / 2;
    root.y0 = 0;
    var nodes = tree.nodes(root).reverse();
    var links = tree.links(nodes);
    var maxDepth = 1;
    var leftMaxTextLength = 0;
    nodes.forEach(function(d) {
        maxDepth = maxDepth > d.depth ? maxDepth : d.depth;
        if (d.GalaxyCluster !== undefined) {
            leftMaxTextLength = leftMaxTextLength > d.GalaxyCluster.value.length ? leftMaxTextLength : d.GalaxyCluster.value.length;
        }
    })
    var offsetLeafLength = leftMaxTextLength * 6.7; // font-size of body is 12px
    var ratioFactor = (width - offsetLeafLength) / maxDepth;
    nodes.forEach(function(d) { d.y = d.depth * ratioFactor; });

    var node = svg.selectAll("g.node")
        .data(nodes, function(d) { return getId(d, true) });

    var nodeEnter = node.enter().append("g")
        .attr("class", "node")
        .attr("transform", function(d) { return "translate(" + d.y + "," + d.x + ")"; })
        .on("mouseover", nodeHover)
        .on("dblclick", nodeDbclick);

    var gEnter = nodeEnter.append('g');
    drawEntities(gEnter);

    var link = svg.selectAll("path.link")
        .data(links, function(d) { return getId(d.target); });

    link.enter().insert("path", "g")
        .attr("class", "link")
        .style("fill", "none")
        .style("stroke", "#ccc")
        .style("stroke-width", "2px")
        .attr("d", function(d) {
            return diagonal(d);
        });
        // .attr("d", d3.linkHorizontal()
        //     .x(function(d) { return d.y; })
        //     .y(function(d) { return d.x; }));
}

function drawEntities(gEnter) {
    gEnter.filter(function(d) { return d.isRoot }).call(drawGalaxy);
    gEnter.filter(function(d) { return d.isVersion === true }).call(drawVersion);
    gEnter.filter(function(d) { return !d.isRoot && d.isVersion !== true }).call(drawCluster);
}

function drawCluster(gEnter) {
    gEnter.append("circle")
        .attr("r", 15)
        .style("fill", "#fff")
        .style("stroke", "steelblue")
        .style("stroke-width", "2px")
    gEnter.append("image")
        .attr("xlink:href", function(d) { 
            return d.GalaxyCluster.default ? '<?= $baseurl ?>/img/orgs/MISP.png' : '<?= $baseurl ?>/img/orgs/' + d.GalaxyCluster.orgc_id + '.png';
        })
        .attr("x", "-12px")
        .attr("y", "-12px")
        .attr("width", "24px")
        .attr("height", "24px")
        .on("error", function() { // avoid broken link image
            d3.select(this).attr("xlink:href", transparentImg);
        });
    gEnter.filter(function(d) { return d.parent && d.parent.isVersion})
        .append("foreignObject")
        .attr("y", "-36px")
        .attr("x", "-5px")
        .attr("width", "12px")
        .attr("height", "16px")
        .append("xhtml:div")
        .append("a")
        .attr("class", "fas fa-arrow-up useCursorPointer")
        .attr("title", "<?= __('Update cluster to parent\'s new version') ?>")
        .attr("href", function(d) { return "<?= sprintf('%s/galaxy_clusters/updateCluster/', $baseurl) ?>" + d.GalaxyCluster.id; })
    
    drawLabel(gEnter, {
        text: function(d) { return getTextFromNode(d, 'cluster'); },
        x: function(d) { return d.children ? "0em" : "1.5em"; },
        dy: function(d) { return d.children ? "2.5em" : ".35em"; },
        textAnchor: function(d) { return d.children ? "middle" : "start"; },
        fontWeight: ''
    });
}

function drawGalaxy(gEnter) {
    gEnter.append("circle")
        .attr("r", 5)
        .style("fill", "lightsteelblue")
        .style("stroke", "steelblue")
        .style("stroke-width", "2px");

    drawLabel(gEnter, {
        text: function(d) { return getTextFromNode(d, 'galaxy') },
        x: function(d) { return d.children ? "0em" : "1.5em"; },
        dy: function(d) { return d.children ? "2em" : ".35em"; },
        textAnchor: "start",
        fontWeight: 'bold'
    });
}
function drawVersion(gEnter) {
    var paddingX = 4;
    gEnter.append("foreignObject")
        .attr("height", 18)
        .attr("y", -9)
        .attr("width", function(d) { return getTextWidth(getTextFromNode(d, 'version')) + 2*paddingX + 'px'; })
        .append("xhtml:div")
        .append("span")
        .attr("class", function(d) { return "label " + (d.children ? "label-warning" : "label-info") })
        .attr("title", function(d) { return d.children ? "Version" : "<?= __('Latest version of the parent cluster') ?>" })
        .html(function(d) { return getTextFromNode(d, 'version') })
}

function drawLabel(gEnter, options) {
    var defaultOptions = {
        text: '',
        x: '',
        dx: '',
        y: '',
        dy: '',
        textAnchor: 'start',
        fontWeight: ''
    }
    options = $.extend(defaultOptions, options);
    gEnter.append("text")
        .attr("dy", options.dy)
        .attr("dx", options.dx)
        .attr("x", options.x)
        .attr("y", options.y)
        .attr("text-anchor", options.textAnchor)
        .attr("font-weight", options.fontWeight)
        .style("fill-opacity", 1)
        .text(options.text);
}

function getTextFromNode(d, nodeType) {
    if (nodeType == 'cluster') {
        return d.GalaxyCluster.value;
    } else if (nodeType == 'galaxy') {
        return d.Galaxy.name + ' galaxy';
    } else if (nodeType == 'version') {
        return d.version;
    } else {
        return '';
    }
}

function getTextWidth(text) {
    var tmp = $('<span></span>').text(text).css('visibility', 'hidden')
    $('body').append(tmp);
    var bcr = tmp[0].getBoundingClientRect()
    tmp.remove();
    return bcr.width;
}

function getId(d) {
    var id = "";
    if (d.isRoot) {
        id = 'root'
    } else if (d.isVersion && !d.isLast) {
        id = 'version-' + d.parentUuid + '-' + d.version;
    } else if (d.isVersion && d.isLast) {
        id = 'version-last-' + d.parentUuid;
    } else {
        id = d.GalaxyCluster.id;
    }
    return id;
}


function nodeDbclick(d) {
    var url;
    var clickedId = '';
    if (d.isRoot) {
        url = "<?= sprintf('%s/galaxies/view/', $baseurl) ?>";
        clickedId = d.Galaxy.id;
    } else if (!d.isRoot && d.isVersion !== true) {
        url = "<?= sprintf('%s/galaxy_clusters/view/', $baseurl) ?>";
        clickedId = d.GalaxyCluster.id;
    }
    if (url !== undefined) {
        url += clickedId;
        var win = window.open(url, '_blank');
    }
}

function nodeHover(d) {
    var $d3Element = $(this);
    var hasTooltip = $d3Element.data('tooltip') !== undefined
    if (!d.isRoot && d.isVersion !== true && !hasTooltip) {
        $d3Element.tooltip({
            html: true,
            container: 'body',
            title: generate_tooltip(d)
        }).tooltip('show')
    }
}

function generate_tooltip(d) {
    var tooltipText = d.isRoot ? d.Galaxy.name : d.GalaxyCluster.description;
    var tooltipVersion = "<?= __('Version:') ?> " + (d.isRoot ? d.Galaxy.version : d.GalaxyCluster.version);
    var tooltipId = "<?= __('ID:') ?> " + (d.isRoot ? d.Galaxy.id : d.GalaxyCluster.id);
    var $div = $('<div></div>').append(
        $('<div class="bold"></div>').css({'text-align': 'left'}).text("<?= __('Description:') ?>"),
        $('<div></div>').css({'text-align': 'left'}).text(tooltipText),
        $('<div class="bold"></div>').css({'text-align': 'left'}).text(tooltipId),
        $('<div class="bold"></div>').css({'text-align': 'left'}).text(tooltipVersion),
    );
    var $table = $('<table class="table table-condensed"></table>');
    if (d.GalaxyElement !== undefined && d.GalaxyElement.length > 0) {
        $body = $('<tbody></tbody>');
        d.GalaxyElement.forEach(function(element) {
            $body.append(
                $('<tr></tr>').append(
                    $('<td></td>').text(element.key),
                    $('<td></td>').text(element.value)
                )
            )
        })
        $table.append($body);
        $div.append(
            $('<div class="bold"></div>').css({'text-align': 'left'}).text("<?= __('Galaxy elements:') ?>"),
            $table
        );
    }
    return $div[0].outerHTML;
}
</script>