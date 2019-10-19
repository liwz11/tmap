var rotated = 0;
var svg_width = 1000;
var svg_height = 800;
var svg_top = 15;

var body_width = document.body.clientWidth;
var svg_right = (body_width - svg_width) / 2;

var init_x, end_x;
var scale = 1;
var translate = [0, 0];
var mouse_pressed = false;

var target_ip = "[TMAP_ADDR]";

var colors = [
    '#00CD00', // target
    '#1E90FF', // normal-in
    '#9B30FF', // normal-out
];

function random_range(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
};

function unitVector(x1, y1, x2, y2) {
    const v = [x2-x1, y2-y1];
    const norm = Math.sqrt(Math.pow(v[0], 2), Math.pow(v[1], 2));
    return [v[0]/norm, v[1]/norm];
};

var toCartesian = axis => d => {
    return projection([d.lon, d.lat])[axis === "x" ? 0 : 1];
};

var projection = d3.geo.mercator()
    .scale(153)
    .translate([svg_width/2, svg_height/1.5])
    .rotate([rotated, 0, 0]);

var path = d3.geo.path()
    .projection(projection);

var zoom = d3.behavior.zoom()
    .scaleExtent([1, 20])
    .on("zoom", zoomed);

var svg = d3.select("body").append("svg")
    .attr("id", "svg")
    .attr("style", "right:"+svg_right+"px; top:"+svg_top+"px;")
    .attr("width", svg_width)
    .attr("height", svg_height)
    .on("mousedown", function() {
        d3.event.preventDefault(); 
        init_x = d3.mouse(this)[0];
        mouse_pressed = true;
    })
    .on("mouseup", function() {
        rotated = rotated + ((d3.mouse(this)[0] - init_x) * 360 / (scale * svg_width));
        mouse_pressed = false;
    })
    .call(zoom);

function zoomed() {
    var h = 0;
    translate = d3.event.translate;
    scale = d3.event.scale; 
    
    translate[0] = Math.min(
        (svg_width / svg_height) * (scale - 1), 
        Math.max(svg_width * (1 - scale), translate[0])
    );

    translate[1] = Math.min(
        h * (scale - 1) + h * scale, 
        Math.max(svg_height * (1 - scale) - h * scale, translate[1])
    );

    zoom.translate(translate);
    if(scale === 1 && mouse_pressed) {
        end_x = d3.mouse(this)[0];
        projection.rotate([rotated + (end_x - init_x) * 360 / (scale * svg_width), 0, 0]);
        g.selectAll('path').attr('d', path);
        svg.selectAll("circle").attr("cx", toCartesian("x"));
        return;
    }

    g.attr("transform", "translate(" + translate + ")scale(" + scale + ")");
    svg.selectAll("circle").attr("transform", "translate(" + translate + ")scale(" + scale + ")");
    d3.selectAll(".boundary").style("stroke-width", 0.5 / scale);
}

var tooltip = d3.select("body").append("div")
    .append("div")
    .attr("class", "tooltip hidden");

d3.select("body").append("div")
    .attr("style", "z-index:4; position:absolute; right:"+(svg_right+svg_width/2-140)+"px;top:"+(svg_top+5)+"px;")
    .append("span")
    .attr("style", "color:#A0A0A0; font-size:24px; font-weight:bold; opacity:1;")
    .html("网络访问实时监测系统");

window.onresize = function() {
    body_width = document.body.clientWidth;
    svg_right = (body_width - svg_width) / 2;
    svg.attr("style", "right:"+svg_right+"px; top:"+svg_top+"px;")

}

////////////////////////////////////////////////

//need this for correct panning
var g = svg.append("g");

// draw map
d3.json("data/world-110m.json", (error, world) => {
    if (error) throw error;

    //countries
    g.append("g")
        .attr("class", "boundary")
        .selectAll("boundary")
        .data(topojson.feature(world, world.objects.countries).features)
        .enter().append("path")
        .attr("name", function(d) {return d.properties.name;})
        .attr("id", function(d) {return d.id;})
        .on('mouseover', hoverActive)
        .on("mousemove", showTooltip)
        .on("mouseout", hoverOut)
        .attr("d", path);
});

function showTooltip(d) {
    var svg_left = parseFloat(window.getComputedStyle(document.getElementById('svg'), null).getPropertyValue("left"));

    label = d.properties.name;
    //label = d3.select(this).attr("name");
    
    var mouse = d3.mouse(svg.node()).map(function(d) {return parseInt(d);});
    if(mouse[0] < svg_width - 180) {
        if(mouse[1] < svg_height - 100) {
            tooltip.classed("hidden", false)
                .attr("style", "left:"+(svg_left+mouse[0]+20)+"px; top:"+(svg_top+mouse[1]+20)+"px;")
                .html(label);
        }
        else {
            tooltip.classed("hidden", false)
                .attr("style", "left:"+(svg_left+mouse[0]+20)+"px; top:"+(svg_top+mouse[1]-30)+"px;")
                .html(label);
        }
    }
    else {
        if(mouse[1] < svg_height - 100) {
            tooltip.classed("hidden", false)
                .attr("style", "right:"+(svg_width-mouse[0]+svg_right+20)+"px; top:"+(svg_top+mouse[1]+20)+"px;")
                .html(label);
        }
        else {
            tooltip.classed("hidden", false)
                .attr("style", "right:"+(svg_width-mouse[0]+svg_right+20)+"px; top:"+(svg_top+mouse[1]-30)+"px;")
                .html(label);
        }
    }
}

function hoverActive() {
    d3.select('.hovered').classed('hovered', false);
    d3.select(this).classed('hovered', true);
}

function hoverOut() {
    tooltip.classed("hidden", true);
    d3.select(this).classed('hovered', false);
}

// draw traffic
function show_traffic(traffic) {
    //console.log(traffic);
    
    var radius = (10/Math.sqrt(scale)) + "px";
    var opacity = 0.8;
    var stroke_width = 3 / Math.sqrt(scale);
    var trans_duration = (traffic.level > 0 ? 1500 : 1000); // 过渡效果持续时间
    var delay = (traffic.level > 0 ? 400 : 10);

    if(traffic.src.ip != target_ip && traffic.dst.ip != target_ip) {
        return;
    }

    if(document.getElementById('target_circle') == null) {
        svg.selectAll("circle")
            .data([(traffic.src.ip == target_ip ? traffic.src : traffic.dst)], d => d.key)
            .enter().append("circle")
            .attr("id", "target_circle")
            .attr("class", "circle")
            .attr("r", radius)
            .attr("stroke", colors[0])
            .attr("stroke-opacity", opacity)
            .attr("stroke-width", stroke_width)
            .attr("fill", "transparent")
            .attr("cx", toCartesian("x"))
            .attr("cy", toCartesian("y"));
    }
    else {
        svg.selectAll("#target_circle")
            .attr("r", radius)
            .attr("stroke-width", stroke_width)
    }

    var impact_radius = () => `${random_range(20, 40) / Math.sqrt(scale)}px`;
    //console.log(traffic.src)
    
    //var circle = svg.selectAll("circle")
    //    .data([(traffic.src.ip == target_ip ? traffic.dst : traffic.src)], d => d.key)
    //    .enter().append("circle")
    var circle = svg.append("circle")
        .data([(traffic.src.ip == target_ip ? traffic.dst : traffic.src)], d => d.key)
        .attr("id", traffic.time)
        .attr("class", "circle")
        .attr("r", radius)
        .attr("stroke", colors[traffic.color_idx])
        .attr("stroke-opacity", opacity)
        .attr("stroke-width", stroke_width)
        .attr("fill", "transparent");

    circle
        .attr("cx", toCartesian("x"))
        .attr("cy", toCartesian("y"))
        .transition().delay(delay).duration(trans_duration).ease("linear")
        .attr("r", impact_radius())
        .attr("stroke-opacity", 0.1)
        .remove();

    svg.selectAll("circle")
        .attr("transform", "translate(" + translate + ")scale(" + scale + ")");
}

var t = 0
setInterval(function() {
    var xmlhttp = new XMLHttpRequest();
    xmlhttp.open("GET", "http://[TMAP_DOMAIN]:[TMAP_PORT]/get_traffic?t=" + t, true);
    xmlhttp.send(null);
    xmlhttp.onreadystatechange = function () {
        if(xmlhttp.readyState == 4 && xmlhttp.status == 200) {
            var res = xmlhttp.responseText;
            //console.log(res);

            var traffic_list = JSON.parse(res);
            if(traffic_list.length > 0) {
                t = traffic_list[traffic_list.length - 1]['time'];

                var t0 = traffic_list[0]['time'];
                for(var i = 0; i < traffic_list.length; i++) {
                    var t1 = traffic_list[i]['time'];
                    setTimeout((function(traffic) {
                        console.log(traffic.dst);
                        show_traffic(traffic);
                    })(traffic_list[i]), t1 - t0);
                }
            }
        }
    }
}, [INTERVAL] * 1000);
