////https://github.com/dchest/fast-sha256-js/blob/master/sha256.js
///https://github.com/dchest/tweetnacl-js/blob/master/nacl.js


var ls_encryption_key=null;
var muid=null;
var ls_state=null;

function reset_state()
{
	ls_encryption_key=null;
	muid=null;
	ls_state=null;
}

function sp2_is_loggedin()
{
	if(muid==null || ls_encryption_key === null || ls_encryption_key.length != 32)
	{
		return false;
	}
	return true;
}


var mlogin_iters=1<<16;
var recovery_iters=1<<16; //todo adjust these

function sp2_login(master_username,mu_password)
{
	var local_muid=sha256(master_username).slice(0,8);
	
	//console.log("Logging in");
	var master_key=sha256.pbkdf2(mu_password,"sp2:"+master_username,mlogin_iters, 32);
	//console.log("Logged in");
	
	ls_encryption_key=master_key;
	muid=local_muid;
//	try
//	{
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
function sp2_delete_muid()
{
	localStorage.removeItem(muidkey(muid));
}
function _ls_get()
{
	if(!sp2_is_loggedin())
	{
		throw new Error("Not logged in");
	}
	if(ls_state !=null)
	{
		return ls_state;
	}
	var item=JSON.parse(localStorage.getItem(muidkey(muid)));
	if(item === null)
	{
		return {};
	}
	nc=str2uint(item.nonce);
	var jsstr=nacl.secretbox.open(str2uint(item.secretbox),nc,ls_encryption_key);
	if(jsstr === null)
	{
		ls_encryption_key=null;
		throw new Error("Master password incorrect for saved muid");
	}
	var dec=new TextDecoder();
	return JSON.parse(dec.decode(jsstr));
}

function _ls_set(key,value)
{
	ls_state=_ls_get();
	var oldval=ls_state[key] || null;
	ls_state[key]=value;
	if(value==null)
	{
		delete ls_state[key];
	}
	var nonce=nacl.randomBytes(24);
	var jsstr=JSON.stringify(ls_state);
	var enc=new TextEncoder();
	var msg=enc.encode(jsstr);
	
	var box=nacl.secretbox(msg,nonce,ls_encryption_key);

	var item={'secretbox':uint2str(box),'nonce':uint2str(nonce)};
	localStorage.setItem(muidkey(muid),JSON.stringify(item));
	return oldval;
}

function sp2_export()
{
	return localStorage.getItem(muidkey(muid));
}
function sp2_import(txt)
{
	localStorage.setItem(muidkey(muid),txt);
	ls_state=null;
	ls_state=_ls_get();
}


function sp2_entry_key(sp_domain,sp_username)
{
	//return "d:\""+sp_domain+"\" u:\""+sp_username+"\"";
	return "d_"+sp_domain+"_u_"+sp_username;
}

function sp2_entry_insert(sp_domain,sp_username,sp_salt,sp_punctuation)
{
	new_entry={'domain':sp_domain,'username':sp_username,'salt':sp_salt,'punctuation':sp_punctuation};
	_ls_set(sp2_entry_key(sp_domain,sp_username),new_entry)
}
function sp2_entry_delete(sp_key)
{
	_ls_set(sp_key,null);
}
function sp2_entry_getall()
{
	return _ls_get();
}
function sp2_entry_get(key)
{
	var e=_ls_get();
	return e[key];
}	

function hexrshift(wao,amount)
{
	var wa=wao;
	var prev=0;
	var i;
	for(i=0;i<wa.length;i++)
	{
		np=wa[i] << (8-amount);
		wa[i] >>>= amount;
		wa[i] |= prev;
		prev = np;
	}
	return wa;
}

function getnext(byt,bits)
{
	var a=byt[31] & ((1 << bits)-1);
	hexrshift(byt,bits);
	return a;
}
//in superpass 2, punctuation is true by default.
function makepassword(byt,length,punctuation)
{
	var character_dictionary='abcdefghijklmnopqrstuvwxyz234567'; //base32 RFC...
	
	var wa=byt;
	var outpw='';
	
	outpw+=String.fromCharCode(65+getnext(wa,4));	//one upper case
	outpw+=String.fromCharCode(97+getnext(wa,4));	//one lower case
	outpw+=String.fromCharCode(50+getnext(wa,3));	//one digit (2-9)

	for(var x=0;x<(length-5);x++)
	{
		outpw+=character_dictionary.charAt(getnext(wa,5));
		//hexprint(cjs,wa);
	}
	if(punctuation)
	{
		outpw+='!';
	}
	else
	{
		outpw+='d';
	}
	outpw+=character_dictionary.charAt(getnext(wa,5));
	return outpw
}

function sp2_superpass(master,domain,username,salt,length,punctuation)
{
	var metasalt=username+"|"+domain.toLowerCase()+"|"+salt;
	var nmaster=master;
	var enc=new TextEncoder();
	metasalt=enc.encode(metasalt);
	nmaster=enc.encode(nmaster);
	var byt=sha256.pbkdf2(nmaster,metasalt,recovery_iters,32);
	
	return makepassword(byt,length,punctuation);
}

$(function()
{
	reset_state();
});
