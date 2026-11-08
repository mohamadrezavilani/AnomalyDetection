import { PGlite } from '@electric-sql/pglite';
import readline from 'node:readline';
const db = await PGlite.create({parsers:{20:value=>BigInt(value)}});
process.stdout.write(JSON.stringify({ready:true})+'\n');
for await (const line of readline.createInterface({input:process.stdin})) {
  try {
    const message=JSON.parse(line);
    // An aborted transaction rejects SET ROLE too. Recovery must reach the
    // engine before the virtual-role adapter issues any further statement.
    if(message.role && !/^\s*ROLLBACK(?:\s|$)/i.test(message.sql))
      await db.exec('SET ROLE "'+message.role.replaceAll('"','""')+'"');
    const result=await db.query(message.sql,message.params||[]);
    for (const row of result.rows) for (const field of result.fields) {
      if(row[field.name]===null) continue;
      if(field.dataTypeID===700||field.dataTypeID===701) row[field.name]={__pg_float:String(row[field.name])};
      if(field.dataTypeID===1700) row[field.name]={__pg_numeric:String(row[field.name])};
    }
    process.stdout.write(JSON.stringify({rows:result.rows,rowcount:result.affectedRows??result.rows.length},
      (_key,value)=>typeof value==='bigint'?{__pg_int:value.toString()}:value instanceof Uint8Array?{__pg_bytes:Buffer.from(value).toString('base64')}:value)+'\n');
  } catch(error) {
    process.stdout.write(JSON.stringify({error:error.message,code:error.code})+'\n');
  }
}
await db.close();
