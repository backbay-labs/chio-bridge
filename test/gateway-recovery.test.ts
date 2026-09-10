import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createGateway, type GatewayConfig } from "../dist/gateway.js";
import { gatewayStatus, recoverGatewayLock } from "../dist/gateway-operator.js";

test("operator recovery verifies dead process ownership and retains pending journal fences",async()=>{
 const directory=mkdtempSync(join(tmpdir(),"chio-recovery-"));const config:GatewayConfig={execution:{endpoint:"http://127.0.0.1:1",bearerToken:"delegated",subjectKey:"ab".repeat(32),trustedSigners:["cd".repeat(32)],capabilityId:"cap",serverId:"fs",sessionId:"kernel"},sessionId:"host",journalDir:directory,tools:[{name:"write_file",inputSchema:{type:"object"}}]};
 const code=`import {createGateway} from ${JSON.stringify(new URL("../dist/gateway.js",import.meta.url).href)};const gateway=createGateway(${JSON.stringify(config)},{execute(){process.stdout.write('pending\\n');return new Promise(()=>{});}});gateway.call(1,'write_file',{path:'one'});setInterval(()=>{},1000);`;
 const child=spawn(process.execPath,["--input-type=module","-e",code],{stdio:["ignore","pipe","pipe"]});
 try{
  await new Promise<void>((resolve,reject)=>{child.stdout.once("data",()=>resolve());child.once("error",reject);child.once("exit",code=>reject(new Error(`child exited ${code}`)));});
  assert.equal(gatewayStatus(config).lock.state,"alive");assert.throws(()=>recoverGatewayLock(config),/alive/);
  const files=readdirSync(directory).filter(name=>name.endsWith(".json"));assert.equal(files.length,1);const before=readFileSync(join(directory,files[0]!),"utf8");
  const exited=new Promise(resolve=>child.once("exit",resolve));child.kill("SIGKILL");await exited;
  assert.equal(gatewayStatus(config).lock.state,"dead");const recovery=recoverGatewayLock(config);assert.equal(recovery.recovered,true);assert.equal(recovery.fenced,true);assert.equal(readFileSync(join(directory,files[0]!),"utf8"),before);
  let dispatches=0;const next=createGateway(config,{async execute(request:any){dispatches++;return{state:"unknown",evidence:"unverified",requestId:request.requestId};}});
  try{assert.equal((await next.call(1,"write_file",{path:"one"})).state,"unknown");assert.equal((await next.call(2,"write_file",{path:"two"})).state,"not_dispatched");assert.equal(dispatches,0);}finally{next.close();}
 }finally{child.kill("SIGKILL");rmSync(directory,{recursive:true,force:true});}
});
