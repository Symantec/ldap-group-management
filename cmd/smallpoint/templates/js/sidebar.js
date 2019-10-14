
// Toggle between showing and hiding the sidebar, and add overlay effect
function sidebar_open() {
    // Get the Sidebar
    var mySidebar = document.getElementById("mySidebar");

    // Get the DIV with overlay effect
    var overlayBg = document.getElementById("myOverlay");

    if (mySidebar.style.display === 'block') {
        mySidebar.style.display = 'none';
        overlayBg.style.display = "none";
    } else {
        mySidebar.style.display = 'block';
        overlayBg.style.display = "block";
    }
}

// Close the sidebar with the close button
function sidebar_close() {
    // Get the Sidebar
    var mySidebar = document.getElementById("mySidebar");

    // Get the DIV with overlay effect
    var overlayBg = document.getElementById("myOverlay");

    mySidebar.style.display = "block";
    overlayBg.style.display = "none";
}

function updateSidebarPendingActionsCount() {
 var ajaxRequest = new XMLHttpRequest();
                ajaxRequest.onreadystatechange = function(){
                        if(ajaxRequest.readyState == 4){
                                if(ajaxRequest.status == 200){
                                        var jsonObj = JSON.parse(ajaxRequest.responseText);
                                        var groups = jsonObj.Groups;
                                        //console.log("groups :" + groups);
					if (groups.length < 1) {
						return
					}
					element = document.getElementById("pending_action_count")
					element.textContent = groups.length;
					element.style.padding = "1px 6px 1px";
                                }
                                else {
                                        console.log("Status error: " + ajaxRequest.status);
                                }
                        }
                }
        ajaxRequest.open('GET', '/getGroups.js?type=pendingActions&encoding=json');
	ajaxRequest.send();
}

document.addEventListener('DOMContentLoaded', function () {
          document.getElementById('hamburger_menu_button').addEventListener('click', sidebar_open);
          document.getElementById('myOverlay').addEventListener('click', sidebar_close);
          updateSidebarPendingActionsCount();
          //  main();
});
