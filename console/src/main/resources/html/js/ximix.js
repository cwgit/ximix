var pollTimer = null;
node_desc = {};
old_node_size = 0;
var lang_id = navigator.language || navigator.userLanguage;
var lang = {};
var rtype = {};
var stype = {};
var MINUTES = 60;
var HOURS = MINUTES * 60;
var DAYS = HOURS * 24;
var ONE_MB = 1024 * 1024;
var nodes = {};
var node_con_state = {}
var stats = {};
var statTimer = null;

var statFetchCtr = 0;

jQuery.ajaxSetup({
    'beforeSend': function (xhr) {
        xhr.setRequestHeader("Accept", "text/javascript")
    }
});

(function ($) {
    // Disable a form field.
    $.fn.disable = function () {
        return this.attr("disabled", "disabled");
    };

    // Enable it again.
    $.fn.enable = function () {
        return this.removeAttr("disabled");
    };
}(jQuery));

var multipleInput = {}


function fetchConfiguredNodes(callback) {
    $.post("/api/nodes/mixnetadmin", null, function (data) {

            for (var n in data) {
                nodes[data[n].hash] = data[n];
            }

            ensureTabs();


            if (callback != null) {
                callback.call();
            }
        }
    );
}


function ensureTabs() {

    var tablist = $('#tab-list');
    var tabbody = $('#tabs');

    for (var k in nodes) {
        $('<li><a href="#' + (k) + '_tab">' + (nodes[k].name) + '</a><img id="' + (k) + '_tab_icon"  src=""/></li>').appendTo(tablist);
        $('<div id="' + (k) + '_tab"><div class="node" id="' + (k) + '_details" >Pending..</div></div>').appendTo(tabbody);
    }

    $("#tabs").tabs();
}


function updateConnected(callback) {
    $.post("/api/connected/mixnetadmin", null, function (data) {

            for (var n in data) {

                var tab = $('#' + (n) + '_tab_icon');
                var detail = $('#' + (n) + '_details');

                if (data[n] != node_con_state[n]) {

                    if (data[n]) {
                        tab.attr('src', "/images/con.gif");
                        fetchDetails(nodes[n]);
                    } else {
                        tab.attr('src', '/images/uncon.gif');
                        detail.html("Not connected.");
                    }
                }
                node_con_state[n] = data[n];

            }

            if (callback != null) {
                callback.call();
            }
        }
    );
}


function fetchDetails(info) {
    $.post("/api/details/mixnetadmin", {name: info.name}, function (data) {
        nodes[data.values.hash] = data.values;
        var node = data.values;

        var info = node['info'];
        var capabilities = node['node.capabilities'];
        var socket = node['socket'];
        var vm = node['vm'];

        var outer = $('#' + (node.hash) + '_details');
        outer.html("");

        //
        // Info block
        //
        $("<div class='nodesubheading'>" + lang['info.title'] + "</div>").appendTo(outer);
        var tab = $("<table class='nodetable' border='0'>");
        tab.appendTo(outer);
        for (var k in info) {
            $("<tr><td class='nodetableL'>" + (k) + "</td><td class='nodetableR'>" + ( info[k]) + "</td></tr>").appendTo(tab);
        }

        //
        // Capabilities.
        //
        $("<div class='nodesubheading'>" + lang['capabilities.title'] + "</div>").appendTo(outer)
        tab = $('<table class="nodetable" border="0">');
        tab.appendTo(outer);

        var bdy = "<ol>";
        for (var k in capabilities) {
            bdy = bdy + "<li>" + (capabilities[k]) + "</li>";
        }
        bdy = bdy + "</ol>";
        $("<tr><td class='nodetableL'>" + (lang['node.capabilities']) + "</td><td class='nodetableR'>" + bdy + "</td></tr>").appendTo(tab);


        //
        // Socket
        //
        $("<div class='nodesubheading'>" + lang['socket.title'] + "</div>").appendTo(outer)
        tab = $("<table class='nodetable' border='0'>");


        tab.appendTo(outer);
        for (var k in socket) {
            var n = 'socket.' + k;
            $("<tr><td class='nodetableL'>" + (lang[n]) + "</td><td class='nodetableR'>" + (  apply_rtype(n, socket[k])) + "</td></tr>").appendTo(tab);
        }


        //
        // Virtual Machine.
        //
        $("<div class='nodesubheading'>" + lang['vm.title'] + "</div>").appendTo(outer)
        tab = $("<table class='nodetable' border='0'>");
        tab.appendTo(outer);
        for (var k in vm) {
            var n = 'vm.' + k;
            $('<tr><td class="nodetableL">' + (lang['vm.' + k]) + '</td><td class="nodetableR">' + (apply_rtype(n, vm[k])) + '</td></tr>').appendTo(tab);
        }

        $("<div class='nodesubheading'>" + lang['vm.plot.title'] + "</div>").appendTo(outer)
        $("<div class='vmplot', id='" + (node.hash) + "_graph_vm'></div>").appendTo(outer);


        $("<div class='nodesubheading'>" + lang['statistics.title'] + "</div>").appendTo(outer);

        $("<table id='" + (node.hash) + "_stats_tab' class='nodetable' border='0'>").appendTo(outer);

    });
}


function memFormatter(v, axis) {
    return Math.floor((v.toFixed(axis.tickDecimals) / ONE_MB)) + "Mb";
}

function plotVMInfo(hash) {
    var st = stats[hash];

    if (st != null) {
        var data_mem = new Array();
        var data_gc = new Array();
        for (var k in st) {
            var datum = st[k];
            data_mem.push([datum['zeit'], datum['vm.free-memory']])
            data_gc.push([datum['zeit'], datum['vm.gc.count.delta']]);
        }

        $.plot("#" + hash + "_graph_vm", [
            { data: data_mem, label: "Free Memory" },
            { data: data_gc, label: "Garbage collections", yaxis: 2}

        ], {
            xaxes: [
                { mode: "time" }
            ],
            yaxes: [
                { min: 0, tickFormatter: memFormatter },
                { min: 0, position: "right"}
            ],
            legend: { position: "sw" }
        });

    }
}


function isSplitKey(n) {
    return  (n.indexOf(":") > -1);
}

function splitKeyIntoContext(n) {
    return n.split(":");
}

function addRowHeading(tab, n) {
    $("<tr><td colspan='2' class='nodetableH'>" + (lang[n]) + "</td></tr>").appendTo(tab);
}

function addRow(tab, name, value, suffix, indent) {
    $("<tr><td class='" + (indent ? "nodetableLi" : "nodetableL") + "'>" + (lang[name]) + (suffix != null ? "(" + suffix + ")" : "") + "   </td>" +
        "<td class='" + (indent ? "nodetableRi" : "nodetableR") + "'>" + (apply_rtype(name, value)) + "</td></tr>").appendTo(tab);
}



function addData(tab, data, indent) {
    for (var k in data) {
        if (isSplitKey(k)) {
            var n = splitKeyIntoContext(k);
            if (n.length == 3) {
                addRow(tab, n[1], data, n[2], indent);
            } else {
                addRow(tab, n[1], data[k], null, indent);
            }
        }

        addRow(tab, k, data[k], null, indent);
    }
}

function repaintStats(hash) {
    var outer = $("#" + hash + "_graph_vm");

    if (outer != null) {

        var tab = $("#" + hash + "_stats_tab");
        tab.html("");

        var values = stats[hash];
        if (values.length > 0) {
            var data = values[values.length - 1];

            for (var k in data) {

                if (isSplitKey(k)) {
                    var n = splitKeyIntoContext(k);
                    if ("tab" === stype[n[0]]) {
                        addRowHeading(tab, n[1]);
                        addData(tab, data[k], true);
                        continue;
                    }

                } else {
                    addRow(tab, k, data[k], null, false);
                }
            }
        }

        plotVMInfo(hash);

    }
}


function requestStatistics(callback) {

    var reqParam = new Array();
    for (var k in node_con_state) {
        if (node_con_state[k]) {
            reqParam.push(nodes[k].name);
        }
    }


    $.post("/api/statistics/mixnetadmin", {name: JSON.stringify(reqParam)}, function (_data) {
        for (var k in _data) {
            var data = _data[k];
            if (data == null) {
                continue;
            }

            var hash = data.values.hash;
            if (stats[hash] == null) {
                stats[hash] = new Array();
            }

            data.values['zeit'] = new Date().getTime();
            var values = stats[hash];
            values.push(data.values);
            while (values.length > 100) {
                values.shift();
            }
            if ($("#" + hash + "_details").is(':visible')) {
                repaintStats(hash);
            }
        }

        if (callback != null) {
            callback.call();
        }
    });


}


function formType(index, command, parameter, ui_parent) {
    if (parameter.vargs) {
        multipleInput[(command.id) + "_" + index] = [(command.id) + "_" + index];

        $("<div><a id='" + (command.id) + "_" + index + "_add' href='#'>Add</a> or <a id='" + (command.id) + "_" + index + "_rem' href='#'>Remove</a></div>").appendTo(ui_parent);

        $("#" + (command.id) + "_" + index + "_add").click(function () {

            var ids = multipleInput["" + (command.id) + "_" + index];
            var last = $("#" + ids[ids.length - 1]);

            $("<div><input name='" + index + "' id='" + (command.id) + "_" + index + "_" + ids.length + "' class='commandinput' type='text'/></div>").appendTo(ui_parent);
            ids.push((command.id) + "_" + index + "_" + ids.length);

            return false;
        });

        $("#" + (command.id) + "_" + index + "_rem").click(function () {

            var ids = multipleInput["" + (command.id) + "_" + index];

            if (ids.length > 1) {
                var last = $("#" + ids[ids.length - 1]);
                last.parent().remove(); // Removes the div..
                ids.pop();
            }

            return false;
        });


    }

    ui_parent.append("<div><input name='" + index + "' id='" + (command.id) + "_" + index + "' class='commandinput' type='text'/></div>");

}


//
//
//

function fetchCommands() {
    $.post("/api/commands/mixnetadmin", null, function (data) {

        console.log(data);

        if (data != null) {

            for (t = 0; t < data.length; t++) {

                node = data[t];

                outer = $("#" + node.id + "_command");
                if (!outer.length) {
                    outer = $("<div class='command' id='" + node.id + "_command'>");
                    outer.appendTo('#commands');
                    outer.append("<div class='commandtitle'>" + node.title + "</div>");
                    form = $("<form class='commandform' id='cmd" + node.id + "'>");
                    form.submit(function () {
                        $("#" + node.id + "_command_err").hide();
                        $("#" + node.id + "_command_err").html("");


                        $.post("/api/invoke/mixnetadmin", form.serialize(), function (data) {
                            if (data != null) {
                                if (data.successful == false) {
                                    $("#" + node.id + "_command_err").html(data.message);
                                    $("#" + node.id + "_command_err").show();
                                }
                            }
                        });
                        return false;
                    });

                    form.append("<input type='hidden' name='cmd' value='" + node.id + "'/>");
                    outer.append(form);
                    tab = $("<table></table>");
                    tab.appendTo(form);


                    if (node.parameters != null) {
                        for (a = 0; a < node.parameters.length; a++) {
                            row = $("<tr></tr>");
                            row.appendTo(tab);

                            param = node.parameters[a];
                            label = $("<td class='commandtext'>" + (param.name) + "</td>");
                            row.append(label);
                            td = $("<td></td>");
                            td.appendTo(row);
                            formType(a, node, param, td);
                        }
                    }
                    form.append("<input type='submit' class='commandbutton' value='Invoke'/>");
                    outer.append("<div id='" + node.id + "_command_err' class='errortxt' style='display:none'></div>");
                }
            }
        }
    });
}

function pollNodes() {
    updateConnected();
}


$(document).ready(function () {


    var l = languages[lang_id.toLocaleLowerCase()];
    if (l == null) {
        l = languages[default_language];
    }

    $.getScript(l, function (data, textStatus, jqxhr) {
        if (jqxhr.status != 200) {
            alert("Unable to find: " + l + " for language " + lang_id.toLowerCase());
        }
    });


    fetchConfiguredNodes(function () {
        pollTimer = setInterval(pollNodes, 5000);
        statTimer = setInterval(requestStatistics, 5000);
    });


    $('#period-selection').change(function () {
        var period = parseInt($(this).val());
        if (period < 5) {
            period = 5;
        }

        period *= 1000;

        if (statTimer != null) {
            clearInterval(statTimer);
        }
        statTimer = setInterval(requestStatistics, period);
    });


});

function apply_rtype(name, value) {
    if (rtype[name] == null) {
        return value;
    }

    switch (rtype[name]) {
        case "mb":
            return  (Math.round((value / ONE_MB) * 1000) / 1000.0) + "mb";
            break;

        case "time":
            return new Date(value);
            break;

        case "hms":
            return dhms(value);
            break;

        case "list":
            return mklist(value);
            break;

        case "map":
            return mkMap(value);
            break;

    }

}


function mkMap(val) {
    var out = "<table>";
    for (var k in val) {
        out = out + "<tr><td>" + k + "</td><td>" + val[k] + "</td></tr>";
    }

    return out + "</table>";
}

function mklist(val) {
    var out = "<ol>";

    for (var v in val) {
        out = out + "<li>" + (val[v]) + "</li>";
    }
    return out + "</ol>";
}

function dhms(milliseconds) {

    var seconds = Math.floor(milliseconds / 1000);

    var days = Math.floor(seconds / DAYS);
    seconds -= (days * DAYS);

    var hours = Math.floor(seconds / HOURS);
    seconds -= (hours * HOURS);

    var minutes = Math.floor(seconds / MINUTES);
    seconds -= (minutes * MINUTES);

    var out = "";
    if (days > 0) {
        out = days + "d ";
    }

    if (hours > 0) {
        out = out + hours + "h ";
    }

    if (minutes > 0) {
        out = out + minutes + "m ";
    }

    return out + seconds + "s";
}