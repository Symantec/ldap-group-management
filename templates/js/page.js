function pagination(arr) {

    var i, j;
    page(arr,1);
    var arr_length=arr.length;
    var text = '<a href="#" onclick="decrease()" class="w3-button">&laquo;</a>';
    var iter = 1;

    for (i = 1, j = 1; i < 4; i++, j++) {
        text += '<a href="#"  class="w3-text-black w3-bar-item w3-button" onclick="page(' + arr + ',' + i + ')">' + j + '</a>';
    }

    text += '<a href="#" onclick="increase(' + arr_length +','+arr+ ')" class="w3-text-black w3-bar-item w3-button">&raquo;</a>';


    document.getElementById("paging").innerHTML = text;
}

function increase(arr_length,arr){
    if(iter<(arr_length/3)-4)
    {
        iter+=3;
    }
    text='<a href="#"onclick="decrease()" class="w3-button">&laquo';
    for(i=iter,j=iter;i<iter+3;i++,j++)
    {
        text+='<a href="#"  class="w3-button" onclick="page(' +arr+','+ i + ')">'+j+'</a>';
    }

    text+='<a href="#" onclick="increase(arr_length,arr)" class="w3-button">&raquo;</a>';


    document.getElementById("paging").innerHTML = text;

}

function decrease(){

    if(iter>1)
        iter-=3;
    text='<a href="#"onclick="decrease()" class="w3-button">&laquo';
    for(i=iter,j=iter;i<iter+3;i++,j++)
    {
        text+='<a href="#"  class="w3-button" onclick="page(' +arr+','+ i + ')">'+j+'</a>';
    }

    text+='<a href="#" onclick="increase(arr)" class="w3-button">&raquo;</a>';


    document.getElementById("paging").innerHTML = text;
}


function myFunction(i) {
    var text2= '';
    if((i*3)+1>=arr.length)
    {

        text2+='<p>'+arr[i*3]+'</p>';
    }
    else
    {
        if((i*3)+2>=arr.length)
        {

            text2+='<p>'+arr[i*3]+'</p>'+
                '<p>'+arr[(i*3)+1]+'</p>';
        }

        else
        {

            text2+='<p>'+arr[i*3]+'</p>'+
                '<p>'+arr[(i*3)+1]+'</p>'+
                '<p>'+arr[(i*3)+2]+'</p>';
        }
    }
    document.getElementById("demo2").innerHTML = text2;
}

function page(arr,i){
    var a=i-1;
    var text2='<tbody>';
    var href_link="http://localhost:11000/group/?groupname=";
    if (12 * (a) + 12 <= arr.length){
        for (j = 12 * a; j <= (12 * a) + 12; j++) {
            text2+='<tr><td><input type="checkbox" id="myCheck"></td><td><a href='+href_link+arr[j]+'>'+arr[j]+'</a></td></tr>'

        }
    }
    else{
        for(j = 12 * a; j > arr.length; j++){
            text2+='<tr><td><input type="checkbox" id="myCheck"></td><td><a href='+href_link+arr[j]+'>'+arr[j]+'</a></td></tr>'

        }

    }
    text2+='</tbody>';
    document.getElementById("display").innerHTML=text2;
}
