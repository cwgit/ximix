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


function fetchNodes() {
    $.post("/api/nodes", null, function (data) {
        if (data != null) {

            for(t=0; t<data.length; t++) {

            node = data[t];

            outer = $("#"+node.hash+"_info");
                if (!outer.length)
                 {
                    outer = $("<div class='node' id='"+node.hash+"'_info'>");
                    outer.appendTo('#nodes');
                    outer.append("<div class='nodetitle'>"+node.hostName+"</div>");
                    outer.append("<table class='nodetable' border='0'>" +
                        " <tr><td>Started:</td><td>"+(new Date(node.started))+"</td></tr>" +
                        "</table>");

                 }
            }
        }
    });
}


$( document ).ready(function() {
     fetchNodes();
});