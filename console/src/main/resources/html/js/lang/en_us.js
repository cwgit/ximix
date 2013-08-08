//
// EN US Language.
//
lang["name"] = "Name";

lang["ui.addplot"]="Plot";
lang["ui.plot.tooltip"]="Plot Statistic.";

lang['info.title']="Node Information";

lang['vm.title']="Virtual Machine Info"
lang['vm.plot.title']="Live Chart"
lang["vm.vendor"] = "JVM";
lang["vm.vendor-name"] = "Vendor";
lang["vm.vendor-version"] = "Version";
lang["vm.available-processors"] = "Processors";
lang["vm.free-memory"] = "Free Memory";
lang["vm.start-time"] = "Start Time";
lang["vm.total-memory"] = "Total Memory";
lang["vm.used-memory"]="Used Memory";
lang["vm.up-time"] = "Up-Time";
lang["capabilities.title"] = "Capabilities";



lang['node.capabilities'] = "Node Capabilities";

lang['socket.title']="Listening Socket"
lang['socket.port']="Listening Port";
lang['socket.bind-address']="Listening Address";
lang['socket.backlog']="Backlog";


lang['statistics.title']="Node Statistics";

lang['vm.gc.count.delta']="GC Count";
lang['vm.gc.time.delta']="GC Time";


//
// Board hosting service statistics.
//
lang["bhs-title"]="Board Hosting Service"
lang["bhs"] = {}
lang["bhs"]["messages-on-board"]="Messages On Board";


//
// prefix to type.
//
stype['bhs']="tab";


rtype["vm.free-memory"] = "mb";
rtype["vm.start-time"] = "time";
rtype["vm.total-memory"] = "mb";
rtype["vm.used-memory"] = "mb";

rtype["vm.up-time"] = "hms";
rtype["node.capabilities"] = "list";
rtype["node.metadata"] = "map";
rtype["board.hosting.service"] = "map";


//
// Allow plot info.
//
allow_plot["vm.gc.count.delta"]={};
allow_plot["vm.gc.time.delta"] ={};
allow_plot["vm.free-memory"]={};
allow_plot["bhs!messages-on-board"]={};
allow_plot["vm.used-memory"]={};

//
// Pre load graph.
//
to_plot.push("vm.free-memory");
to_plot.push("vm.gc.count.delta");