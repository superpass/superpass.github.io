////https://github.com/dchest/fast-sha256-js/blob/master/sha256.js
///https://github.com/dchest/tweetnacl-js/blob/master/nacl.js


var ls_encryption_key=null;
var muid=null;
var ls_state=null
function sp2_is_loggedin()
{
	if(muid==null || ls_encryption_key === null || ls_encryption_key.length != 32)
	{
		return false;
	}
	return true;
}

function sp2_login(master_username,mu_password)
{
	var local_muid=sha256(master_username).slice(0,8);
	
	var master_key=sha256.pbkdf2(master_username+mu_password,"superpass2",1<<16, 32);
	
	ls_encryption_key=master_key;
	muid=local_muid;
	//try
	//{
		ls_state=_ls_get();
	//}
	//catch(err)
	//{
	//	throw new Error("Master password incorrect for saved muid");
	//}
}
function str2uint(s)
{
	var ao=new Uint8Array(s.length/2);
	for(var i=0;i<ao.length;i++)
	{
		ao[i]=Number.parseInt(s.substring(2*i,2*i+2),16);
	}
	return ao;
}
function uint2str(u)
{
	var so="";
	for(var i=0;i<u.length;i++)
	{
		so+=u[i].toString(16).padStart(2,"0");
	}
	return so;
}
function muidkey(muid)
{
	var sm='muid'+uint2str(muid);
	return sm;
}
function delete_muid()
{
	localStorage.removeItem(muidkey(muid));
}
function _ls_get()
{
	if(!sp2_is_loggedin())
	{
		throw new Error("Not logged in");
	}
	var item=JSON.parse(localStorage.getItem(muidkey(muid)));
	if(item === null)
	{
		return {};
	}
	nc=str2uint(item.nonce);
	var jsstr=nacl.secretbox.open(str2uint(item.secretbox),nc,ls_encryption_key);
	var dec=new TextDecoder();
	return JSON.parse(dec.decode(jsstr));
}

function _ls_set(key,value)
{
	ls_state=_ls_get();
	var oldval=ls_state[key] || null;
	ls_state[key]=value;
	var nonce=nacl.randomBytes(24);
	var jsstr=JSON.stringify(ls_state);
	var enc=new TextEncoder();
	var msg=enc.encode(jsstr);
	
	var box=nacl.secretbox(msg,nonce,ls_encryption_key);
	testdec=nacl.secretbox.open(box,nonce,ls_encryption_key);
	//console.log(testdec);
	//console.log(msg);

	var item={'secretbox':uint2str(box),'nonce':uint2str(nonce)};
	localStorage.setItem(muidkey(muid),JSON.stringify(item));
	return oldval;
}

$(function()
{
	//console.log(sp2_is_loggedin());
	sp2_login('steve132','hello');
	//console.log(sp2_is_loggedin());
	_ls_set('testkey','stuff');
});
