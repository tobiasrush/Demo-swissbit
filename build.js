#!/usr/bin/env node

/**
 * Build script to copy npm packages from node_modules to vendor directory
 * This is required for Vercel deployment since node_modules is not served as static files
 */

import { cpSync, mkdirSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const packages = [
  {
    name: '@ideem/zsm-client-sdk',
    files: [
      'ErrorHandler.js',
      'EventCoordinator.js',
      'FIDO2Client.js',
      'FIDO2ClientBase.js',
      'GlobalScoping.js',
      'IdentityIndexing.js',
      'PluginManager.js',
      'RelyingParty.js',
      'RelyingPartyBase.js',
      'UMFAClient.js',
      'UMFAClientBase.js',
      'Utils.js',
      'WASMRustInterface.js',
      'WebAuthnClient.js',
      'WebAuthnClientBase.js',
      'ZSMClientSDK.js',
      'LICENSE',
      'README.md',
      'CHANGELOG.md'
    ]
  },
  {
    name: '@ideem/plugins.passkeys-plus',
    files: [
      'FIDO2Client.js',
      'PKPUtils.js',
      'PasskeysPlusClient.js',
      'PasskeysPlus.js',
      'RelyingParty.js',
      'UMFAClient.js',
      'WebAuthnClient.js',
      'LICENSE',
      'README.md',
      'CHANGELOG.md'
    ]
  }
];

function copyPackage(pkg) {
  const sourceDir = join(__dirname, 'node_modules', pkg.name);
  const targetDir = join(__dirname, 'vendor', pkg.name);

  if (!existsSync(sourceDir)) {
    console.error(`Error: ${sourceDir} not found. Run 'npm install' first.`);
    process.exit(1);
  }

  // Create target directory
  mkdirSync(targetDir, { recursive: true });

  // Copy each file
  pkg.files.forEach(file => {
    const sourceFile = join(sourceDir, file);
    const targetFile = join(targetDir, file);

    if (existsSync(sourceFile)) {
      cpSync(sourceFile, targetFile, { recursive: false });
      console.log(`Copied: ${pkg.name}/${file}`);
    } else {
      console.warn(`Warning: ${sourceFile} not found, skipping...`);
    }
  });

  // Copy directories if specified
  if (pkg.directories) {
    pkg.directories.forEach(dir => {
      const sourceDirPath = join(sourceDir, dir);
      const targetDirPath = join(targetDir, dir);

      if (existsSync(sourceDirPath)) {
        cpSync(sourceDirPath, targetDirPath, { recursive: true });
        console.log(`Copied directory: ${pkg.name}/${dir}/`);
      } else {
        console.warn(`Warning: ${sourceDirPath} not found, skipping...`);
      }
    });
  }

  // Copy package.json for reference
  const packageJsonSource = join(sourceDir, 'package.json');
  const packageJsonTarget = join(targetDir, 'package.json');
  if (existsSync(packageJsonSource)) {
    cpSync(packageJsonSource, packageJsonTarget);
  }
}

console.log('Building vendor directory from node_modules...\n');

packages.forEach(copyPackage);

console.log('\nBuild complete!');
