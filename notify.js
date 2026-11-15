const webpush=require("web-push");
/* RÉGLAGES (mêmes valeurs que dans index.html) */
const CFG={url:"https://fyqyzzgygsstmqvnasps.supabase.co",key:"sb_publishable_ex-1Mrg3qfgwAbaSeFwCQQ_3G2Uq8p4",vapid:"BCkPa_Cx91QddcV3zW_9UffcVId7BuV_kOJRTlI-kTZp4ub3Dfkq-CkE6zJH06U34UyV0BYXbDHXWlR9JT2GyzM",subject:"mailto:lebusinessman008@gmail.com"};
module.exports=async(req,res)=>{
  if(req.method!=="POST")return res.status(405).end();
  try{
    const{kind,ref}=req.body||{};
    const r=await fetch(CFG.url+"/rest/v1/rpc/push_targets",{method:"POST",headers:{"Content-Type":"application/json",apikey:CFG.key,Authorization:req.headers.authorization||""},body:JSON.stringify({p_kind:kind,p_ref:String(ref)})});
    if(!r.ok)return res.status(403).json({error:await r.text()});
    const rows=await r.json();
    webpush.setVapidDetails(CFG.subject,CFG.vapid,process.env.VAPID_PRIVATE_KEY);
    const out=await Promise.allSettled(rows.map(x=>webpush.sendNotification({endpoint:x.endpoint,keys:{p256dh:x.key_p256dh,auth:x.key_auth}},JSON.stringify({title:x.title,body:x.body}))));
    res.json({sent:out.filter(o=>o.status==="fulfilled").length,total:rows.length});
  }catch(e){res.status(500).json({error:String(e)})}
};
