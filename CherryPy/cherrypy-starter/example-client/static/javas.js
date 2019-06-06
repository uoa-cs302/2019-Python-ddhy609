"use strict";

$(document).ready(function(){
    //Feed
    $("#tabFeed").on('click', function(){
        /* $.get("/get_database_messages", function(data) {
            //window.alert(data)
            var data_array_value = data.split('/n')
            var i;
            $('#feed').append("<br>");
            for (i = 0; i < data_array_value.length; i++) {
                //text_array += data_array_value[i]
                //$('#feed').html(text_array + "<br />") 
                $('#feed').append(data_array_value[i] + '<br>')               
            }
            
            //$('#feed').html(text_array + "<br />")
        }); */
    });

    //Messages
    $("#tabMessages").on('click', function(){
        /*code-source: https://www.pair.com/support/kb/how-to-use-jquery-to-show-hide-a-form-on-click/ */
        /*$("#messageBox").toggle()*/
    });

    //Form information send
    $('form').on('submit', function(event) {
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
        
        $('#feed').html("");
        $.get("/get_database_messages", function(data) {
            //window.alert(data)
            var data_array_value = data.split('/n')
            var i;
            $('#feed').append("<br>");
            for (i = 0; i < data_array_value.length; i++) {
                //text_array += data_array_value[i]
                //$('#feed').html(text_array + "<br />") 
                $('#feed').append(data_array_value[i] + '<br>')               
            }
            
            //$('#feed').html(text_array + "<br />")
        });

      /*   var xhr = new XMLHttpRequest();
        xhr.open('POST','/tx_broadcast',true);
        //xhr.withCredentials = false;
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr.send("message="+input); */
        return false;
    });

    //Account Info
    $("#tabAccountInfo").on('click', function(){
       
    });

    //Settings
    $("#tabSettings").on('click', function(){
        
    });

    //Home
    $("#tabHome").on('click', function(){
        
    });


    //Public Message (Broadcast)
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