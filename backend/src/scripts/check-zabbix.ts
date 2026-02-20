
import { parseArgs } from 'node:util';
import process from 'node:process';

const { values } = parseArgs({
  options: {
    url: { type: 'string' },
    user: { type: 'string' },
    password: { type: 'string' },
  },
});

if (!values.url || !values.user || !values.password) {
  console.error('Usage: tsx check-zabbix.ts --url <url> --user <user> --password <pass>');
  process.exit(1);
}

const url = values.url.replace(/\/api_jsonrpc\.php$/, '') + '/api_jsonrpc.php';

console.log(`Testing connection to: ${url}`);

async function test() {
  try {
    const body = {
      jsonrpc: '2.0',
      method: 'user.login',
      params: { user: values.user, password: values.password },
      id: 1,
    };

    console.log('Sending request...');
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json-rpc' },
      body: JSON.stringify(body),
    });

    console.log(`Status: ${res.status} ${res.statusText}`);
    
    if (!res.ok) {
        console.error('HTTP Error!');
        process.exit(1);
    }
    
    const json = await res.json() as any;
    console.log('Response body:', JSON.stringify(json, null, 2));

    if (json.error) {
       console.error('Zabbix API Error:', json.error.message);
       process.exit(1);
    }

    console.log('SUCCESS! Auth token received.');
  } catch (err: any) {
    console.error('FETCH ERROR:', err.message);
    if (err.cause) {
      console.error('CAUSE:', err.cause);
    }
    process.exit(1);
  }
}

test();
