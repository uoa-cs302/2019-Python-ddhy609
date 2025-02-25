"use strict";

//global variable storing last db for easy update
var temp_data_array=[];
var reverse_try = 0;
var userUPI = 0;




async function IntervalFunction(){
    await setInterval(callReport, 5000)
    await setInterval(refreshDataFeed, 2000);
    await setInterval(displaying_online_people, 2000)
    
}

$(document).ready(function(){

    IntervalFunction()
    //Form information send
    $('#boxBroadcast').on('submit', function(event) {
        // Prevent the page from reloading
        //event.preventDefault();
        
        // Set the text-output span to the value of the first input
        var $input = $(this).find('input');
        var input = $input.val();
        
        //$('#text-output').text("You typed: " + input);

        $.ajax({
            type: "POST",
            url: "/tx_broadcast",
            data: "message="+input,
            error : function(){
                window.alert("Couldn't send message")
            }
        })

        

        //$('#feed').html("");
        /* $.get("/get_database_messages", function(data) {

            //getting new array
            var data_array_value = data.split('/n')
            
            var arrLen = (data_array_value.length) - (temp_data_array.length)
            var length_oldDb = temp_data_array.length

            var i;
            
            
            for (i = 0; i < arrLen; i++) {
                $('#feed').append(data_array_value[length_oldDb+i] + '<br>'  )               
            }

            //storing new array into old array
            temp_data_array = data_array_value
        }); */
        $("#send_text").val("")
        refreshDataFeed()
      /*   var xhr = new XMLHttpRequest();
        xhr.open('POST','/tx_broadcast',true);
        //xhr.withCredentials = false;
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr.send("message="+input); */
        return false;
    });


    $('#boxMessage').on('submit', function(event) {
        // Prevent the page from reloading
        //event.preventDefault();
        
        // Set the text-output span to the value of the first input
        var $input = $(this).find('input');
        var input = $input.val();
          
        //$('#text-output').text("You typed: " + input);
        //window.alert(userUPI + input)

        // JSON.stringify prevents AJAX from processing DATA 
        ////parcel = JSON.stringify([userUPI, input])

        // @Note - NAME input parameter of python same as ajax
        // i.e "parcel="
        //upi, message
        $.ajax({
            type: "POST",
            url: "/send_private_message",
            data: {upi : userUPI, message : input},
            error : function(){
                window.alert("Couldn't send message to selected user")
            }
        })
        $("#send_text").val("")
 
        return false;
    });

    //remove at end
    $("#headingTitle").on('click', function(){
          /*$.ajax({
            type: "GET",
            url: "/get_database_messages",
            error : function(){
                window.alert("No messages to show")
            },
            success: function(data){
                window.alert(data)
                $('#feed').text("Data retrieved is: " + data)
            }
        })*/


        //THIS ONE IS WORKING:
        /* $('#feed').html("");
        $.get("/get_database_messages", function(data) {
            //window.alert(data)
            var data_array_value = data.split('/n')
            var i;
            $('#feed').append("<br>");
            for (i = 0; i < data_array_value.length; i++) {
                $('#feed').append(data_array_value[i] + '<br>')               
            }
        }); */

        //source-code: https://www.w3schools.com/jquery/jquery_ajax_get_post.asp 
         /* $.get("/get_database_messages", function(data) {
            //window.alert(data)
            var data_array_value = data.split('/n')
            window.alert(data_array_value);
            window.alert(data_array_value.length)
            console.log(data_array_value);
            var i;
            var text_array = ""
            //window.alert(data.length)
            $('#feed').append("<br>");
            for (i = 0; i < data_array_value.length; i++) {
                //text_array += data_array_value[i]
                //$('#feed').html(text_array + "<br />") 
                $('#feed').append(data_array_value[i] + '<br>')               
            }
            
            //$('#feed').html(text_array + "<br />")
        }); */
    });
});

function refreshDataFeed(){
    //$('#feed').html("");
    //console.log("refresh being called")

    $.get("/get_database_messages", function(data) {
        //window.alert(data)
       //getting new array
       var data_array_value = data.split('/n')
       var arrLen = (data_array_value.length) - (temp_data_array.length)
       var length_oldDb = temp_data_array.length
       var i;
       
        if(reverse_try ==1) {
            for (i = 0; i < arrLen; i++) {
                $('#broadcastMessages').prepend(data_array_value[i] + '<br>')
            }
        } 
        
       //$('#broadcastMessages').html("")
        if(reverse_try ==0) {
            for (i = 0; i < arrLen; i++) {
                $('#broadcastMessages').append(data_array_value[i] + '<br>')
            }
            reverse_try =1;
        }
 

       //storing new array into old array
       temp_data_array = data_array_value
   });
} 




function callReport(){ 
    $.ajax({
        type: "POST",
        url: "/call_report",
        data: "status="+"online",
        error : function(){
            //window.alert("Couldn't send message")
        },
        success: function(){

            //window.alert("REPORT SUCCESS")
        }
    })
}


function userDisp(username){
    $("#mainHeading").text("Message")
    $("#mainHeading").append(" (" + username.id + ")")
    userUPI = username.id
    /* console.log(user.id)
    console.log("User printed")
    window.alert(user.id) */
}

//display online users
function displaying_online_people(){
//$("#online_Users").click(function(){
    $.get("/get_online_people", function(data){
        var user_lists = data.split("/n")
        //window.alert(userElements)
        $("#online_Users").html("Online Users:")
        $("#online_Users").append("<br>" + "<br>")
        for (var i = 0; i < user_lists.length; i++){
            //$selectedUser = ("<a/>", {href:"#", onclick:userID(userElements[i]), id:userElements[i]});
            //$("#onlineUsers").append("<a href=https://www.google.com>" + userElements[i] + "<br>")
            //$("#onlineUsers").append($selectedUser)
            $("#online_Users").append("<a onclick=userDisp("+ user_lists[i] + ") " + "id="+user_lists[i]+">" + user_lists[i] + "<br>")
            //;return false;
        }
    })
    //window.alert($(this).id)
//});
}


