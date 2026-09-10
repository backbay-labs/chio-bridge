// Real kernel and independent Docker resource qualification. No host acceptance.
import assert from "node:assert/strict";
import { readFileSync,writeFileSync,mkdirSync } from "node:fs";
import { join,resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

const [packageDir,configPath,operatorPath,outputPath,mode]=process.argv.slice(2);
if(![packageDir,configPath,operatorPath,outputPath].every(value=>value&&resolve(value)===value)||!["ordinary","approval"].includes(mode))throw new Error("usage: MODULE_DIR CONFIG OPERATOR NEW_EVIDENCE_DIR ordinary|approval");
mkdirSync(outputPath,{recursive:false});
const {startGatewayHttp}=await import(pathToFileURL(join(packageDir,"dist/index.js")).href);
const config=JSON.parse(readFileSync(configPath,"utf8"));const operator=JSON.parse(readFileSync(operatorPath,"utf8"));
if(mode==="approval"){
 config.approval={requiredTools:config.tools.map(tool=>tool.name),purpose:"Review exact qualification content",ttlSeconds:300};
 writeFileSync(configPath,JSON.stringify(config,null,2)+"\n",{mode:0o600});
}
function command(args){const p=spawnSync(args[0],args.slice(1),{encoding:"utf8"});if(p.status!==0)throw new Error(p.stderr||`command failed ${p.status}`);return p.stdout;}
function observe(){
 return JSON.parse(command(["docker","run","--rm","--network","none","--read-only","--mount",`type=volume,src=${operator.volume},dst=/observe,readonly`,"--mount",`type=volume,src=${operator.auditVolume},dst=/audit,readonly`,"--entrypoint","node",operator.image,"-e","const f=require('fs');const files={};for(const n of f.readdirSync('/observe'))if(f.lstatSync('/observe/'+n).isFile())files[n]=f.readFileSync('/observe/'+n,'utf8');const p='/audit/dispatch.jsonl';console.log(JSON.stringify({files,dispatch:f.existsSync(p)?f.readFileSync(p,'utf8').split('\\n').filter(Boolean).map(JSON.parse):[]}));"]));
}
const records=[];const record=(name,value)=>{records.push({name,...value});writeFileSync(join(outputPath,"cases.json"),JSON.stringify(records,null,2)+"\n");};
const transport=await startGatewayHttp(config);let session="";let count=0;
async function rpc(method,params){
 const response=await fetch(transport.url,{method:"POST",headers:{"Content-Type":"application/json",Authorization:`Bearer ${transport.token}`,...(session?{"Mcp-Session-Id":session}:{})},body:JSON.stringify({jsonrpc:"2.0",id:++count,method,params})});
 if(method==="initialize")session=response.headers.get("mcp-session-id");
 assert.equal(response.status,200);return response.json();
}
async function call(name,args){
 const raw=await rpc("tools/call",{name,arguments:args});const outcome=JSON.parse(raw.result.content[0].text);
 if(outcome.state==="completed"){const ack=await rpc("chio/acknowledge",outcome.delivery);assert.equal(ack.result.acknowledged,true);}
 return {raw,outcome};
}
try{
 await rpc("initialize",{protocolVersion:"2025-11-25"});const inventory=await rpc("tools/list",{});
 assert.equal(inventory.result.tools.length,mode==="approval"?5:4);record("discovery",{passed:true,inventory});
 const args={path:`/workspace/bridge-${mode}.txt`,content:`actual ${mode} effect\n`};const first=await call("write_file",args);
 if(mode==="ordinary"){
  assert.equal(first.outcome.state,"completed");assert.equal(first.outcome.evidence,"verified");assert.equal(observe().files[`bridge-${mode}.txt`],args.content);record("write",{passed:true,...first,resource:observe()});
  const read=await call("read_text_file",{path:args.path});assert.equal(read.outcome.state,"completed");record("read-after-acknowledgement",{passed:true,...read});
  const before=observe();const forbidden=await call("read_text_file",{path:"/workspace/secret.txt"});assert.equal(forbidden.outcome.state,"denied");
  const after=observe();assert.equal(after.dispatch.length,before.dispatch.length);record("forbidden-read-no-dispatch",{passed:true,...forbidden,resource:after});
 }else{
  assert.equal(first.outcome.state,"awaiting_approval");assert.equal(observe().dispatch.length,0);record("pending-no-dispatch",{passed:true,...first,resource:observe()});
  const resume={requestId:first.outcome.requestId,tool:"write_file",arguments:args};const missing=await call("chio_resume",resume);assert.equal(missing.outcome.state,"awaiting_approval");assert.equal(observe().dispatch.length,0);
  const cli=join(packageDir,"dist/gateway-operator.js");const submission=join(outputPath,"submission.json");
  command([process.execPath,cli,"approval-submit",configPath,first.outcome.requestId,operatorPath,submission]);const submitted=JSON.parse(readFileSync(submission,"utf8"));
  command([process.execPath,cli,"approval-decide",configPath,first.outcome.requestId,operatorPath,submitted.record.id,"approved"]);
  const complete=await call("chio_resume",resume);assert.equal(complete.outcome.state,"completed");assert.equal(observe().files["bridge-approval.txt"],args.content);record("explicit-approved-resume",{passed:true,...complete,resource:observe()});
  const replay=await call("chio_resume",resume);assert.equal(replay.outcome.state,"completed");assert.equal(observe().dispatch.length,1);record("completed-resume-no-redispatch",{passed:true,...replay});
  const deniedArgs={path:"/workspace/bridge-rejected.txt",content:"must not appear"};const next=await call("write_file",deniedArgs);assert.equal(next.outcome.state,"awaiting_approval");
  const rejection=join(outputPath,"rejection-submission.json");command([process.execPath,cli,"approval-submit",configPath,next.outcome.requestId,operatorPath,rejection]);
  command([process.execPath,cli,"approval-decide",configPath,next.outcome.requestId,operatorPath,JSON.parse(readFileSync(rejection,"utf8")).record.id,"denied"]);
  const refused=await call("chio_resume",{requestId:next.outcome.requestId,tool:"write_file",arguments:deniedArgs});assert.equal(refused.outcome.state,"not_dispatched");assert.equal(observe().dispatch.length,1);assert.equal(observe().files["bridge-rejected.txt"],undefined);record("operator-rejection-no-dispatch",{passed:true,...refused,resource:observe()});
 }
 const hidden=await rpc("resources/read",{uri:"file:///workspace/secret.txt"});assert.equal(hidden.error.code,-32601);record("unsupported-resource-route",{passed:true,response:hidden});
 const before=observe();await transport.close();await assert.rejects(()=>call("write_file",{path:"/workspace/after-close.txt",content:"must not appear"}));assert.deepEqual(observe(),before);record("closed-transport-no-effect",{passed:true,resource:observe()});
}finally{await transport.close();}
writeFileSync(join(outputPath,"identity.json"),JSON.stringify({claim:"shared bridge and kernel qualification only",kernelSha256:operator.kernelSha256,image:operator.image,volume:operator.volume,auditVolume:operator.auditVolume,mode,packageDir,configSha256:createHash("sha256").update(readFileSync(configPath)).digest("hex"),cases:records.length},null,2)+"\n");
console.log(JSON.stringify({passed:records.length,skipped:0,mode,outputPath}));
