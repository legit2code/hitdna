import fs from 'fs';
import path from 'path';

function walk(dir: string, fileList: string[] = []): string[] {
  if (!fs.existsSync(dir)) return fileList;
  const files = fs.readdirSync(dir);
  for (const file of files) {
    const full = path.join(dir, file);
    if (fs.statSync(full).isDirectory()) {
      if (file !== 'node_modules' && file !== 'dist' && file !== '.git' && file !== 'coverage') {
        walk(full, fileList);
      }
    } else if (file.endsWith('.ts') || file.endsWith('.tsx') || file.endsWith('.js')) {
      fileList.push(full);
    }
  }
  return fileList;
}

export function runCodemod(targetDirs: string[]) {
  let totalReplaced = 0;
  for (const targetDir of targetDirs) {
    const files = walk(targetDir);
    let dirReplaced = 0;
    for (const file of files) {
      let content = fs.readFileSync(file, 'utf-8');
      
      // Pattern 1: from ['"]../../packages/<pkg>/src/index(.ts)?['"] -> from '@caim/<pkg>'
      let updated = content.replace(
        /from\s+(['"])(\.\.\/)+packages\/([^/'"]+)\/src\/index(?:\.ts)?(['"])/g,
        'from $1@caim/$3$4'
      );

      // Pattern 2: import(['"]../../packages/<pkg>/src/index(.ts)?['"]) -> import('@caim/<pkg>')
      updated = updated.replace(
        /import\s*\(\s*(['"])(\.\.\/)+packages\/([^/'"]+)\/src\/index(?:\.ts)?(['"])\s*\)/g,
        'import($1@caim/$3$4)'
      );

      // Pattern 3: from ['"]../../packages/<pkg>/src/(.+)['"] -> from '@caim/<pkg>/$2'
      updated = updated.replace(
        /from\s+(['"])(\.\.\/)+packages\/([^/'"]+)\/src\/([^'"]+)(['"])/g,
        'from $1@caim/$3/$4$5'
      );

      // Pattern 4: import(['"]../../packages/<pkg>/src/(.+)['"]) -> import('@caim/<pkg>/$2')
      updated = updated.replace(
        /import\s*\(\s*(['"])(\.\.\/)+packages\/([^/'"]+)\/src\/([^'"]+)(['"])\s*\)/g,
        'import($1@caim/$3/$4$5)'
      );

      // Pattern 5: Handle single dot relative in tests: from '@caim/<pkg>/index(.ts)?'
      updated = updated.replace(
        /from\s+(['"])\.\.\/packages\/([^/'"]+)\/src\/index(?:\.ts)?(['"])/g,
        'from $1@caim/$2$3'
      );
      updated = updated.replace(
        /from\s+(['"])\.\.\/packages\/([^/'"]+)\/src\/([^'"]+)(['"])/g,
        'from $1@caim/$2/$3$4'
      );

      if (updated !== content) {
        fs.writeFileSync(file, updated, 'utf-8');
        dirReplaced++;
        totalReplaced++;
        console.log(`Updated: ${file}`);
      }
    }
    console.log(`[codemod] Directory ${targetDir}: updated ${dirReplaced} files.`);
  }
  console.log(`[codemod] Total updated files: ${totalReplaced}`);
}

const target = process.argv[2] ? [process.argv[2]] : ['apps', 'workers', 'packages', 'src', 'tests', 'scripts'];
runCodemod(target);
