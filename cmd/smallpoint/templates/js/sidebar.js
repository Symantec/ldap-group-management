
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

document.addEventListener('DOMContentLoaded', function () {
          document.getElementById('hamburger_menu_button').addEventListener('click', sidebar_open);
          document.getElementById('myOverlay').addEventListener('click', sidebar_close);
          //  main();
});
