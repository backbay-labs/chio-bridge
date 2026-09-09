import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync,readFileSync,writeFileSync,rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startGatewayHttp } from "../dist/gateway-http.js";
import { signedCompletion } from "./helpers/completed.ts";

async function fixture(){
 const dir=mkdtempSync(join(tmpdir(),"chio-http-lifecycle-"));const marker=join(dir,"resource.txt");
 const keys=generateKeyPairSync("ed25519");const signer=keys.publicKey.export({type:"spki",format:"der"}).subarray(-32).toString("hex");const seed=keys.privateKey.export({type:"pkcs8",format:"der"}).subarray(-32).toString("hex");
 const config={execution:{endpoint:"",bearerToken:"fixture-delegated",subjectKey:"ab".repeat(32),trustedSigners:[signer],capabilityId:"cap",serverId:"fs",sessionId:"kernel"},sessionId:"host",journalDir:join(dir,"journal"),tools:[{name:"write_file",inputSchema:{type:"object"}}]};
 let effects=0;
 const owner=createServer(async(request,response)=>{
  let text="";for await(const chunk of request)text+=chunk;const message=JSON.parse(text);let result:any={};
  if(message.method==="chio/execution-context"){
   const now=Math.floor(Date.now()/1000);result={schema:"chio.mcp.execution-context.v1",evidenceVersion:"1",deliveryAcknowledgementVersion:"1",subjectKey:config.execution.subjectKey,capabilityIds:["cap"],serverId:"fs",sessionCredential:{schema:"chio.mcp.session-credential.v1",sessionId:"kernel",subjectKey:config.execution.subjectKey,capabilityIds:["cap"],serverId:"fs",endpointPath:"/mcp",allowedTools:["write_file"],issuedAt:now,expiresAt:now+300}};
  }else if(message.method==="tools/call"){
   effects++;writeFileSync(marker,String(message.params.arguments.content));
   const outcome=signedCompletion(config.execution,{tool:message.params.name,arguments:message.params.arguments,requestId:message.params._meta.chioRequestId},seed);
   result={_meta:{chioEvidence:{schema:"chio.mcp.execution-evidence.v1",requestId:outcome.requestId,receipt:outcome.receipt,output:outcome.result,outputKind:"value",terminalState:"completed"},chioDelivery:outcome.delivery}};
  }else if(message.method==="chio/acknowledge")result={schema:message.params.schema,requestId:message.params.requestId,receiptId:message.params.receiptId,acknowledged:true};
  else assert.fail("unbounded method reached owner");
  response.writeHead(200,{"Content-Type":"application/json"}).end(JSON.stringify({jsonrpc:"2.0",id:message.id,result}));
 });
 await new Promise<void>(resolve=>owner.listen(0,"127.0.0.1",resolve));const address=owner.address();assert.ok(address&&typeof address!=="string");config.execution.endpoint=`http://127.0.0.1:${address.port}`;
 return{config,marker,effects:()=>effects,async close(){owner.closeAllConnections();await new Promise<void>(resolve=>owner.close(()=>resolve()));rmSync(dir,{recursive:true,force:true});}};
}
async function client(transport:{url:string;token:string}){
 let session="";const request=async(message:any,token=transport.token)=>fetch(transport.url,{method:"POST",headers:{"Content-Type":"application/json",Authorization:`Bearer ${token}`,...(session?{"Mcp-Session-Id":session}:{})},body:JSON.stringify(message)});
 const response=await request({jsonrpc:"2.0",id:0,method:"initialize",params:{protocolVersion:"2025-11-25"}});assert.equal(response.status,200);session=response.headers.get("mcp-session-id")!;assert.ok(session);await response.json();
 return{request,async call(id:number,content:string){return (await request({jsonrpc:"2.0",id,method:"tools/call",params:{name:"write_file",arguments:{path:"allowed.txt",content}}})).json();}};
}
test("HTTP guest transport exposes only bounded tools and closing it removes authority route",async()=>{
 const f=await fixture();const transport=await startGatewayHttp(f.config);
 try{
  const c=await client(transport);assert.equal((await c.request({jsonrpc:"2.0",id:1,method:"tools/list"},"wrong")).status,403);
  const hidden=await (await c.request({jsonrpc:"2.0",id:2,method:"resources/read",params:{uri:"file:///private"}})).json();assert.equal(hidden.error.code,-32601);assert.equal(f.effects(),0);
  const first=await c.call(3,"one actual resource effect");assert.equal(JSON.parse(first.result.content[0].text).state,"completed");assert.equal(readFileSync(f.marker,"utf8"),"one actual resource effect");
  await transport.close();await assert.rejects(()=>c.call(4,"must not write"));assert.equal(f.effects(),1);assert.equal(readFileSync(f.marker,"utf8"),"one actual resource effect");
 }finally{await transport.close();await f.close();}
});
test("killing launcher process removes transport even while a separate client remains alive",async()=>{
 const f=await fixture();const module=new URL("../dist/gateway-http.js",import.meta.url).href;
 const code=`import {startGatewayHttp} from ${JSON.stringify(module)};const transport=await startGatewayHttp(${JSON.stringify(f.config)});process.stdout.write(JSON.stringify({url:transport.url,token:transport.token})+'\\n');`;
 const child=spawn(process.execPath,["--input-type=module","-e",code],{stdio:["ignore","pipe","pipe"]});
 try{
  const transport=await new Promise<any>((resolve,reject)=>{let text="";child.stdout.on("data",bytes=>{text+=bytes;if(text.includes("\n"))resolve(JSON.parse(text));});child.once("error",reject);child.once("exit",code=>reject(new Error(`launcher exited early: ${code}`)));});
  const c=await client(transport);await c.call(1,"before launcher death");assert.equal(readFileSync(f.marker,"utf8"),"before launcher death");
  const ended=new Promise(resolve=>child.once("exit",resolve));child.kill("SIGKILL");await ended;
  await assert.rejects(()=>c.call(2,"after launcher death"));assert.equal(f.effects(),1);assert.equal(readFileSync(f.marker,"utf8"),"before launcher death");
 }finally{child.kill("SIGKILL");await f.close();}
});
