import { writeDefaultConfig } from '../lib/config.js';
import { color } from '../lib/color.js';

export function cmdInit(cwd: string): void {
  const { configFile, notesFile } = writeDefaultConfig(cwd);
  console.log(color.green('✓') + ' Initialized agent-receipt');
  console.log(`  config: ${configFile}`);
  console.log(`  notes:  ${notesFile}`);
  console.log('');
  console.log('Next steps:');
  console.log('  agent-receipt capture --agent cursor --message "session notes"');
  console.log('  agent-receipt last');
  console.log('  agent-receipt install-hooks   # optional auto-capture on commit');
}
