<div>
    <h6>
        <a class="" href="<?= sprintf('%s/galaxies/view/%s/context:all', $baseurl, $galaxy_id) ?>">
            <i class="<?php echo $this->FontAwesome->findNamespace($galaxy['Galaxy']['icon']); ?> fa-arrow-left"></i>
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
    var maxDepth = 0;
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
        .data(nodes, function(d) { return d.isRoot ? 'root' : d.GalaxyCluster.id; });

    var nodeEnter = node.enter().append("g")
        .attr("class", "node")
        .attr("transform", function(d) { return "translate(" + d.y + "," + d.x + ")"; })
        .on("mouseover", nodeHover)
        .on("dblclick", nodeDbclick);

    var gEnter = nodeEnter.append('g');
    gEnter.append("circle")
        .attr("r", function(d) { return d.isRoot ? 5 : 15 })
        .style("fill", function(d) { return d.isRoot ? "lightsteelblue" : "#fff"; })
        .style("stroke", "steelblue")
        .style("stroke-width", "2px")
    gEnter.append("image")
        .attr("xlink:href", function(d) { 
            if (d.isRoot) {
                return transparentImg;
            } else {
                return d.GalaxyCluster.default ? '<?= $baseurl ?>/img/orgs/MISP.png' : '<?= $baseurl ?>/img/orgs/' + d.GalaxyCluster.orgc_id + '.png';
            }
        })
        .attr("x", "-12px")
        .attr("y", "-12px")
        .attr("width", "24px")
        .attr("height", "24px")
        .on("error", function() { // avoid broken link image
            d3.select(this).attr("xlink:href", transparentImg);
        });

    nodeEnter.append("text")
        .attr("dy",  function(d) { return d.children ? "2.5em" : ".35em"; })
        .attr("x", function(d) { return d.children ? "0em" : "1.5em"; })
        .attr("text-anchor", function(d) { return d.children ? (d.isRoot ? "start" : "middle") : "start"; })
        .text(function(d) { return d.isRoot ? d.Galaxy.name + ' galaxy' : d.GalaxyCluster.value; })
        .style("fill-opacity", 1)
        .style("font-weight", function(d) { return d.isRoot ? 'bold' : ''});

    var link = svg.selectAll("path.link")
        .data(links, function(d) { return d.target.GalaxyCluster.id; });

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

function nodeDbclick(d) {
    var url, clickedId
    if (d.isRoot) {
        url = "<?= sprintf('%s/galaxies/view/', $baseurl) ?>";
        clickedId = d.Galaxy.id;
    } else {
        url = "<?= sprintf('%s/galaxy_clusters/view/', $baseurl) ?>";
        clickedId = d.GalaxyCluster.id;
    }
    url += clickedId;
    var win = window.open(url, '_blank');
}

function nodeHover(d) {
    var $d3Element = $(this);
    $d3Element.tooltip({
        html: true,
        container: 'body',
        title: generate_tooltip(d)
    }).tooltip('show')
}

function generate_tooltip(d) {
    var tooltipText = d.isRoot ? d.Galaxy.name : d.GalaxyCluster.description;
    var $div = $('<div></div>').append($('<div></div>').text(tooltipText));
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
            $('<h6></h6>').css({'text-align': 'left'}).text("<?= __('Galaxy elements:') ?>"),
            $table
        );
    }
    return $div[0].outerHTML;
}
</script>