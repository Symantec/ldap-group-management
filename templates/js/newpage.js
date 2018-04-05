var i, j;
var arr_length=arr.length;
var iter = 1;
var text = '<a href="#" onclick="decrease('+iter+')" class="w3-button">&laquo;</a>';


for (i = 1, j = 1; i < 4; i++, j++) {
    text += '<a href="#'+i+'"  class="w3-text-black w3-bar-item w3-button" onclick=page(' + i + ')>' + j + '</a>';
}
text += '<a href="#" onclick="increase(' +(iter+2)+')" class="w3-text-black w3-bar-item w3-button">&raquo;</a>';


document.getElementById("paging").innerHTML = text;
page(1);

function increase(iter){
    if(iter<(arr_length/3)-4)
    {
        iter+=3;
    }
    text='<a href="#"onclick="decrease()" class="w3-button">&laquo';
    for(i=iter,j=iter;i<iter+3;i++,j++)
    {
        text+='<a href="#"  class="w3-button" onclick=page({'+ i + ')">'+j+'</a>';
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
        text+='<a href="#"  class="w3-button" onclick="page('+ i + ')">'+j+'</a>';
    }

    text+='<a href="#" onclick="increase('+(iter+2)+')" class="w3-button">&raquo;</a>';


    document.getElementById("paging").innerHTML = text;
}


function page(i){
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

<ul>
{{range $groupname := .Groups}}
<li><a href="/group/?groupname='{{$groupname}}'">{{$groupname}}</a></li>
{{end}}
</ul>