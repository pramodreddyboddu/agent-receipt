import { writeDefaultConfig } from '../lib/config.js';

export function cmdInit(cwd: string): void {
  const { configFile, notesFile } = writeDefaultConfig(cwd);
  console.log('Initialized agent-receipt.');
  console.log(`  config: ${configFile}`);
  console.log(`  notes:  ${notesFile}`);
  console.log('');
  console.log('Next: agent-receipt capture --message "first receipt"');
}
