var labelType, useGradients, nativeTextSupport, animate;

(function() {
  var ua = navigator.userAgent,
      iStuff = ua.match(/iPhone/i) || ua.match(/iPad/i),
      typeOfCanvas = typeof HTMLCanvasElement,
      nativeCanvasSupport = (typeOfCanvas == 'object' || typeOfCanvas == 'function'),
      textSupport = nativeCanvasSupport 
        && (typeof document.createElement('canvas').getContext('2d').fillText == 'function');
  //I'm setting this based on the fact that ExCanvas provides text support for IE
  //and that as of today iPhone/iPad current text support is lame
  labelType = (!nativeCanvasSupport || (textSupport && !iStuff))? 'Native' : 'HTML';
  nativeTextSupport = labelType == 'Native';
  useGradients = nativeCanvasSupport;
  animate = !(iStuff || !nativeCanvasSupport);
})();

var Log = {
  elem: false,
  write: function(text){
    if (!this.elem) 
      this.elem = document.getElementById('log');
    this.elem.innerHTML = text;
    this.elem.style.left = (500 - this.elem.offsetWidth / 2) + 'px';
  }
};

function init(){
    //init data
    var json = {
    "children": [
        {
            "children": [
                {
                    "data": {
                        "relation": "Some text to customize here for <b>192.168.43.9</b> +**+<br><a href=\"javascript:popup_window('https://www.google.com', 'title_title', 600, 600);\">Some actions Here</a>"
                    },
                    "id": "2",
                    "name": "192.168.43.9"
                },
                {
                    "children": [
                        {
                            "data": {
                                "relation": "Some text to customize here for ICMP +***+<br><a href=\"javascript:popup_window('https://www.google.com', 'title_title', 600, 600);\">Some actions Here</a>"
                            },
                            "id": "3",
                            "name": "ICMP"
                        },
                        {
                            "children": [
                                {
                                    "data": {
                                        "relation": "Some text to customize here for 0 +****+<br><a href=\"javascript:popup_window('https://www.google.com', 'title_title', 600, 600);\">Some actions Here</a>"
                                    },
                                    "id": "4",
                                    "name": "0"
                                },
                                {
                                    "children": [],
                                    "data": {
                                        "relation": "Some text to customize here for 0 +****+<br><a href=\"javascript:popup_window('https://www.google.com', 'title_title', 600, 600);\">Some actions Here</a>"
                                    },
                                    "id": "4",
                                    "name": "0"
                                }
                            ],
                            "data": {
                                "relation": "Some text to customize here for ICMP +***+<br><a href=\"javascript:popup_window('https://www.google.com', 'title_title', 600, 600);\">Some actions Here</a>"
                            },
                            "id": "3",
                            "name": "ICMP"
                        }
                    ],
                    "data": {
                        "relation": "Some text to customize here for <b>192.168.43.9</b> +**+<br><a href=\"javascript:popup_window('https://www.google.com', 'title_title', 600, 600);\">Some actions Here</a>"
                    },
                    "id": "2",
                    "name": "192.168.43.9"
                }
            ],
            "data": {
                "relation": "Some text to customize here for 60:33:4b:13:c5:58 +*+<br><a href=\"javascript:popup_window('https://www.google.com', 'title_title', 600, 600);\">Some actions Here</a>"
            },
            "id": "1",
            "name": "## 60:33:4b:13:c5:58"
        }
    ],
    "data": {
        "relation": "<center><h2>174.137.42.65<br>02:1a:11:f0:c8:3b</h2></center>"
    },
    "id": "0",
    "name": "174.137.42.65<br>02:1a:11:f0:c8:3b"
}

	    //init RGraph
    var rgraph = new $jit.RGraph({
        //Where to append the visualization
        injectInto: 'infovis',
        //Optional: create a background canvas that plots
        //concentric circles color
        background: {
          CanvasStyles: {
            strokeStyle: '#555'
          }
        },
        //Add navigation capabilities:
        //zooming by scrolling and panning.
        Navigation: {
          enable: true,
          panning: true,
          zooming: 10
        },
        //Set Node and Edge styles.
        Node: {
            color: '#FF0000'
        },
        
        Edge: {
          color: '#0000FF',
          lineWidth:2
        },

        onBeforeCompute: function(node){
            //Log.write("centering " + node.name + "...");
            //Add the relation list in the right column.
            //This list is taken from the data property of each JSON node.
            $jit.id('inner-details').innerHTML = node.data.relation;
        },
        
        //Add the name of the node in the correponding label
        //and a click handler to move the graph.
        //This method is called once, on label creation.
        onCreateLabel: function(domElement, node){
            domElement.innerHTML = node.name;
            domElement.onclick = function(){
                rgraph.onClick(node.id, {
                    onComplete: function() {
                        //Log.write("OK");
                    }
                });
            };
        },
        //Change some label dom properties.
        //This method is called each time a label is plotted.
        onPlaceLabel: function(domElement, node){
            var style = domElement.style;
            style.display = '';
            style.cursor = 'pointer';

            if (node._depth == 0) {
                style.fontSize = "1em";
				style.background = "#000000";
                style.color = "#FFFFFF";			
				if (node.name == "Malicious") 
				{
					style.background = "#ee3118";
				}
				else if (node.name == "Suspicious") 
				{
					style.background = "#eeba2e";
				}									
            } 
			else if(node._depth == 1){
                style.fontSize = "0.8em";
                //style.color = "#494949";
				style.color = "#BE53A6";
				style.background = "#ffffff";		
				if (node.name == "Malicious") 
				{
					style.background = "#ee3118";
				}
				else if (node.name == "Suspicious") 
				{
					style.background = "#eeba2e";
				}					
				if (node.name.search("ORIGIN") >= 0)
				{
					style.background = "#cc1bee";
					style.color = "#FEFF4C";
				}  				
            } else if(node._depth == 2){
                style.fontSize = "0.7em";
                //style.color = "#494949";
				style.color = "#FC49A6";
				style.background = "#eee91c";
				if (node.name == "Malicious") 
				{
					style.background = "#ee3118";
				}
				else if (node.name == "Suspicious") 
				{
					style.background = "#eeba2e";
				}					
				if (node.name.search("ORIGIN") >= 0)
				{
					style.background = "#cc1bee";
					style.color = "#FEFF4C";
				} 				
            
            } else if(node._depth == 3){
                style.fontSize = "0.7em";
                //style.color = "#494949";
				style.background = "#5bee37";
				style.color = "#000000";
				if (node.name == "Malicious") 
				{
					style.background = "#ee3118";
				}
				else if (node.name == "Suspicious") 
				{
					style.background = "#eeba2e";
				}					
				if (node.name.search("ORIGIN") >= 0)
				{
					style.background = "#cc1bee";
					style.color = "#FEFF4C";
				}    				
            } else if(node._depth == 4){
                style.fontSize = "0.7em";
                //style.color = "#494949";
				style.background = "#ee79ec";
				style.color = "#000000";
				if (node.name == "Malicious") 
				{
					style.background = "#ee3118";
				}
				else if (node.name == "Suspicious") 
				{
					style.background = "#eeba2e";
				}					
				if (node.name.search("ORIGIN") >= 0)
				{
					style.background = "#cc1bee";
					style.color = "#FEFF4C";
				}             
            } else if(node._depth == 5){
                style.fontSize = "0.7em";
                //style.color = "#494949";
				style.background = "#97eaee";
				style.color = "#000000";
				if (node.name == "Malicious") 
				{
					style.background = "#ee3118";
				}
				else if (node.name == "Suspicious") 
				{
					style.background = "#eeba2e";
				}					
				if (node.name.search("ORIGIN") >= 0)
				{
					style.background = "#cc1bee";
					style.color = "#FEFF4C";
				}             
            }			
			else {
                style.display = 'none';
            }

            var left = parseInt(style.left);
            var w = domElement.offsetWidth;
            style.left = (left - w / 2) + 'px';
        }
    });
    //load JSON data
    rgraph.loadJSON(json);
    //trigger small animation
    rgraph.graph.eachNode(function(n) {
      var pos = n.getPos();
      pos.setc(-200, -200);
    });
    rgraph.compute('end');
    rgraph.fx.animate({
      modes:['polar'],
      duration: 2000
    });
    //end
    //append information about the root relations in the right column
    $jit.id('inner-details').innerHTML = rgraph.graph.getNode(rgraph.root).data.relation;
}