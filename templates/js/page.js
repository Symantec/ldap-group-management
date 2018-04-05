//var arr={{.Groups}};
var i, j;
var arr_length=arr.length;
console.log(arr_length);
function Minimum(a,b) {
    if(a>b)return b;
    else return a;
}
var iter = 1;
var text = '<a href="#" onclick="decrease()" class="w3-button">&laquo;</a>';


for (i = 1, j = 1; i <  Minimum(6,(arr_length/12)+1); i++, j++) {
    text += '<a href="#'+i+'"  class="w3-text-black w3-bar-item w3-button" onclick=page(' + i + ')>' + j + '</a>';
}
text += '<a href="#" onclick="increase()" class="w3-text-black w3-bar-item w3-button">&raquo;</a>';


document.getElementById("paging").innerHTML = text;
page(iter);

function increase(){
    if(iter<(arr_length/12)-6)
    {
        iter+=5;
    }
    text='<a href="#" onclick="decrease()" class="w3-button">&laquo';
    for(i=iter,j=iter;i<Minimum(iter+5,(arr_length/12)+1);i++,j++)
    {
        text+='<a href="#'+i+'"  class="w3-button" onclick=page('+ i + ')>'+j+'</a>';
    }

    text+='<a href="#" onclick="increase()" class="w3-button">&raquo;</a>';


    document.getElementById("paging").innerHTML = text;

}

function decrease(){
    if(iter>1)
        iter-=5;
    text='<a href="#" onclick="decrease()" class="w3-button">&laquo';
    for(i=iter,j=iter;i<Minimum(iter+5,(arr_length/12)+1);i++,j++)
    {
        text+='<a href="#'+i+'"  class="w3-button" onclick="page('+ i + ')">'+j+'</a>';
    }

    text+='<a href="#" onclick="increase()" class="w3-button">&raquo;</a>';


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
    }else{
        for(j = 12 * a; j < arr.length; j++){
            var value_2=arr[j];
            //console.log(value);
            text2+='<tr><td><input type="checkbox" id="myCheck"></td><td><a href='+href_link+value_2+'>'+value_2+'</a></td></tr>'

        }

    }
    text2+='</tbody>';
    document.getElementById("display").innerHTML=text2;
}
