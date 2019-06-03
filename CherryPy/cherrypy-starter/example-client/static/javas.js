
$(document).ready(function(){
    //Feed
    $("#tabFeed").on('click', function(){
        $("#headingTitle").html("Feed")
        $("#feed").html("")
        $("#messageBox").hide()
    });

    //Messages
    $("#tabMessages").on('click', function(){
        $("#headingTitle").html("Messages")
        $("#feed").html("")
        $("#messageBox").show()
    });

    /* $("#sendMessage").on('click', function(){
        $("#headingTitle").html("Messages")
        $("#feed").html("")
        $("#messageBox").show()
    }); */

    //Account Info
    $("#tabAccountInfo").on('click', function(){
        $("#headingTitle").html("Account Info")
        $("#feed").html("")
        $("#messageBox").hide()
    });

    //Settings
    $("#tabSettings").on('click', function(){
        $("#headingTitle").html("Settings")
        $("#feed").html("")
        $("#messageBox").hide()
    });

    //Home
    $("#tabHome").on('click', function(){
        $("#headingTitle").html("PiChat")
        $("#feed").html("Welcome to PiChat")
        $("#messageBox").hide()
    });
});