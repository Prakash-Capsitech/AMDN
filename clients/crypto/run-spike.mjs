import { offlineExchange } from './spike.mjs';

try {
  console.log(JSON.stringify(await offlineExchange(), null, 2));
} catch {
  console.error('F0 encryption spike failed. Run the synthetic tests for diagnosis; do not log client state.');
  process.exitCode = 1;
}
