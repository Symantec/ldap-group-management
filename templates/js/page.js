function increase(iter,arr_length){
    if(iter<(arr_length/3)-4)
    {
        iter+=3;
    }
    text='<a href="#"onclick="decrease()" class="w3-button">&laquo';
    for(i=iter,j=iter;i<iter+3;i++,j++)
    {
        text+='<a href="#"  class="w3-button" onclick=page({{.Groups}},'+ i + ')">'+j+'</a>';
    }

    text+='<a href="#" onclick="increase('+(iter+2)+','+arr.length+')" class="w3-button">&raquo;</a>';


    document.getElementById("paging").innerHTML = text;

}

function decrease(iter){
    if(iter>1)
        iter-=3;
    text='<a href="#"onclick="decrease('+iter+')" class="w3-button">&laquo';
    for(i=iter,j=iter;i<iter+3;i++,j++)
    {
        text+='<a href="#"  class="w3-button" onclick="page({{.Groups}},'+ i + ')">'+j+'</a>';
    }

    text+='<a href="#" onclick="increase('+(iter+2)+','+(arr.length)+')" class="w3-button">&raquo;</a>';


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
    //console.log(arr);
    //console.log(arr[0]);
    var a=i-1;
    var text2='<tbody>';
    var href_link="http://localhost:11000/group/?groupname=";
    if (12 * (a) + 12 <= arr.length){
        for (j = 12 * a; j <= (12 * a) + 12; j++) {
            var value=arr[j];
            //console.log(value);
            text2+='<tr><td><input type="checkbox" id="myCheck"></td><td><a href='+href_link+value+'>'+value+'</a></td></tr>'

        }
    }
    else{
        for(j = 12 * a; j > arr.length; j++){
            var value_2=arr[j];
            //console.log(value);
            text2+='<tr><td><input type="checkbox" id="myCheck"></td><td><a href='+href_link+value_2+'>'+value_2+'</a></td></tr>'

        }

    }
    text2+='</tbody>';
    document.getElementById("display").innerHTML=text2;
}

function pagination(arr) {
    console.log(arr);
    console.log(arr[0]);
    var i, j;
    //page(arr,1);
    var arr_length=arr.length;
    var iter = 1;
    var text = '<a href="#" onclick="decrease('+iter+')" class="w3-button">&laquo;</a>';


    for (i = 1, j = 1; i < 4; i++, j++) {
        text += '<a href="#'+i+'"  class="w3-text-black w3-bar-item w3-button" onclick=page({{.Groups}},' + i + ')>' + j + '</a>';
    }

    text += '<a href="#" onclick="increase(' +(iter+2)+','+(arr.length)+')" class="w3-text-black w3-bar-item w3-button">&raquo;</a>';


    document.getElementById("paging").innerHTML = text;
   page(arr,1);

}
