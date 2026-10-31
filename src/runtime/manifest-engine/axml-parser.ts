/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Binary Android XML (AXML / ResXMLTree) Parser
 * Decodes compiled AndroidManifest.xml into structured metadata and formatted XML.
 */

import { AndroidManifestData, AndroidActivity, AndroidComponent } from '../core/types';

// Chunk Types
const RES_NULL_TYPE = 0x0000;
const RES_STRING_POOL_TYPE = 0x0001;
const RES_XML_TYPE = 0x0003;
const RES_XML_RESOURCE_MAP_TYPE = 0x0180;
const RES_XML_START_NAMESPACE_TYPE = 0x0100;
const RES_XML_END_NAMESPACE_TYPE = 0x0101;
const RES_XML_START_ELEMENT_TYPE = 0x0102;
const RES_XML_END_ELEMENT_TYPE = 0x0103;
const RES_XML_CDATA_TYPE = 0x0104;

// Attribute Data Types
const TYPE_NULL = 0x00;
const TYPE_REFERENCE = 0x01;
const TYPE_ATTRIBUTE = 0x02;
const TYPE_STRING = 0x03;
const TYPE_FLOAT = 0x04;
const TYPE_DIMENSION = 0x05;
const TYPE_FRACTION = 0x06;
const TYPE_INT_DEC = 0x10;
const TYPE_INT_HEX = 0x11;
const TYPE_INT_BOOLEAN = 0x12;
const TYPE_INT_COLOR_ARGB8 = 0x1c;
const TYPE_INT_COLOR_RGB8 = 0x1d;
const TYPE_INT_COLOR_ARGB4 = 0x1e;
const TYPE_INT_COLOR_RGB4 = 0x1f;

// Well-known Android resource attribute IDs
const RES_ATTR_VERSION_CODE = 0x0101021b;
const RES_ATTR_VERSION_NAME = 0x0101021c;
const RES_ATTR_NAME = 0x01010003;
const RES_ATTR_LABEL = 0x01010001;
const RES_ATTR_ICON = 0x01010002;
const RES_ATTR_MIN_SDK = 0x0101020c;
const RES_ATTR_TARGET_SDK = 0x01010270;
const RES_ATTR_MAX_SDK = 0x01010271;
const RES_ATTR_EXPORTED = 0x01010010;
const RES_ATTR_THEME = 0x01010000;

interface ParsedAttribute {
  namespaceUri: string;
  name: string;
  value: string | number | boolean;
  resId?: number;
}

interface ParsedElement {
  tag: string;
  attributes: ParsedAttribute[];
  children: ParsedElement[];
  parent?: ParsedElement;
}

export class AxmlParseError extends Error {
  constructor(message: string) {
    super(`Binary XML Error: ${message}`);
    this.name = 'AxmlParseError';
  }
}

export function parseBinaryAndroidManifest(buffer: Uint8Array): AndroidManifestData {
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  if (buffer.byteLength < 8) {
    throw new AxmlParseError('File too small to be a valid Android binary XML.');
  }

  const fileType = view.getUint16(0, true);
  if (fileType !== RES_XML_TYPE) {
    // If it's already plain text XML, handle as fallback
    const text = new TextDecoder('utf-8').decode(buffer);
    if (text.includes('<manifest') || text.includes('<?xml')) {
      return parsePlainTextManifest(text);
    }
    throw new AxmlParseError(`Invalid AXML magic type: expected 0x0003, got 0x${fileType.toString(16)}`);
  }

  const headerSize = view.getUint16(2, true);
  const fileSize = view.getUint32(4, true);

  let offset = headerSize;
  let stringPool: string[] = [];
  let resourceIds: number[] = [];

  const rootElements: ParsedElement[] = [];
  const elementStack: ParsedElement[] = [];

  while (offset < buffer.byteLength && offset < fileSize) {
    if (offset + 8 > buffer.byteLength) break;

    const chunkType = view.getUint16(offset, true);
    const chunkHeaderSize = view.getUint16(offset + 2, true);
    const chunkSize = view.getUint32(offset + 4, true);

    if (chunkSize <= 0 || offset + chunkSize > buffer.byteLength + 1024) {
      throw new AxmlParseError(`Corrupted chunk size (${chunkSize}) at offset 0x${offset.toString(16)}`);
    }

    switch (chunkType) {
      case RES_STRING_POOL_TYPE: {
        stringPool = parseStringPool(buffer, offset, chunkSize);
        break;
      }

      case RES_XML_RESOURCE_MAP_TYPE: {
        const idCount = (chunkSize - chunkHeaderSize) / 4;
        resourceIds = [];
        for (let i = 0; i < idCount; i++) {
          resourceIds.push(view.getUint32(offset + chunkHeaderSize + i * 4, true));
        }
        break;
      }

      case RES_XML_START_ELEMENT_TYPE: {
        const line = view.getUint32(offset + 8, true);
        const comment = view.getUint32(offset + 12, true);
        const nsIdx = view.getUint32(offset + 16, true);
        const nameIdx = view.getUint32(offset + 20, true);
        const attrStart = view.getUint16(offset + 24, true);
        const attrSize = view.getUint16(offset + 26, true);
        const attrCount = view.getUint16(offset + 28, true);

        const tagName = getString(stringPool, nameIdx);
        const attributes: ParsedAttribute[] = [];

        let attrOffset = offset + attrStart;
        for (let a = 0; a < attrCount; a++) {
          if (attrOffset + 20 > buffer.byteLength) break;

          const attrNsIdx = view.getUint32(attrOffset, true);
          const attrNameIdx = view.getUint32(attrOffset + 4, true);
          const rawValIdx = view.getUint32(attrOffset + 8, true);
          const valSize = view.getUint16(attrOffset + 12, true);
          const dataType = view.getUint8(attrOffset + 14);
          const dataVal = view.getUint32(attrOffset + 16, true);

          const attrNs = getString(stringPool, attrNsIdx);
          const attrName = getString(stringPool, attrNameIdx);
          const rawVal = getString(stringPool, rawValIdx);

          let attrValue: string | number | boolean = rawVal;

          if (dataType === TYPE_STRING) {
            attrValue = getString(stringPool, dataVal) || rawVal;
          } else if (dataType === TYPE_INT_BOOLEAN) {
            attrValue = dataVal !== 0;
          } else if (dataType === TYPE_INT_DEC || dataType === TYPE_INT_HEX) {
            attrValue = dataVal;
          } else if (dataType === TYPE_REFERENCE) {
            attrValue = `@0x${dataVal.toString(16)}`;
          }

          const resId = resourceIds[attrNameIdx];

          attributes.push({
            namespaceUri: attrNs,
            name: attrName,
            value: attrValue,
            resId,
          });

          attrOffset += attrSize || 20;
        }

        const newElement: ParsedElement = {
          tag: tagName,
          attributes,
          children: [],
        };

        if (elementStack.length > 0) {
          const parent = elementStack[elementStack.length - 1];
          newElement.parent = parent;
          parent.children.push(newElement);
        } else {
          rootElements.push(newElement);
        }

        elementStack.push(newElement);
        break;
      }

      case RES_XML_END_ELEMENT_TYPE: {
        elementStack.pop();
        break;
      }

      case RES_XML_START_NAMESPACE_TYPE:
      case RES_XML_END_NAMESPACE_TYPE:
      case RES_XML_CDATA_TYPE:
      default:
        // Handled cleanly
        break;
    }

    offset += chunkSize;
  }

  const root = rootElements[0];
  if (!root) {
    throw new AxmlParseError('No root XML element found in manifest.');
  }

  return extractManifestData(root);
}

function parseStringPool(buffer: Uint8Array, offset: number, chunkSize: number): string[] {
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const stringCount = view.getUint32(offset + 8, true);
  const styleCount = view.getUint32(offset + 12, true);
  const flags = view.getUint32(offset + 16, true);
  const stringsStart = view.getUint32(offset + 20, true);
  const isUtf8 = (flags & (1 << 8)) !== 0;

  const stringOffsets: number[] = [];
  const baseOffsets = offset + 28;
  for (let i = 0; i < stringCount; i++) {
    stringOffsets.push(view.getUint32(baseOffsets + i * 4, true));
  }

  const strings: string[] = [];
  const poolBase = offset + stringsStart;

  for (let i = 0; i < stringCount; i++) {
    const strOffset = poolBase + stringOffsets[i];
    if (strOffset >= buffer.byteLength) {
      strings.push('');
      continue;
    }

    if (isUtf8) {
      // UTF-8 string pool: 1 or 2 bytes char count, 1 or 2 bytes byte length, utf8 string, 0x00
      let cur = strOffset;
      // Skip char length
      if (buffer[cur] & 0x80) cur += 2;
      else cur += 1;
      // Read byte length
      let byteLen = buffer[cur];
      if (byteLen & 0x80) {
        byteLen = ((byteLen & 0x7f) << 8) | buffer[cur + 1];
        cur += 2;
      } else {
        cur += 1;
      }

      const strBytes = buffer.subarray(cur, cur + byteLen);
      strings.push(new TextDecoder('utf-8').decode(strBytes));
    } else {
      // UTF-16LE string pool: 2 or 4 bytes char count, utf16le string, 0x0000
      let cur = strOffset;
      let charLen = view.getUint16(cur, true);
      cur += 2;
      if (charLen & 0x8000) {
        charLen = ((charLen & 0x7fff) << 16) | view.getUint16(cur, true);
        cur += 2;
      }

      const byteLen = charLen * 2;
      const strBytes = buffer.subarray(cur, cur + byteLen);
      strings.push(new TextDecoder('utf-16le').decode(strBytes));
    }
  }

  return strings;
}

function getString(pool: string[], index: number): string {
  if (index >= 0 && index < pool.length) {
    return pool[index] ?? '';
  }
  return '';
}

function extractManifestData(root: ParsedElement): AndroidManifestData {
  let packageName = '';
  let versionCode = 1;
  let versionName = '1.0';
  let minSdkVersion = 21;
  let targetSdkVersion = 33;
  let maxSdkVersion: number | undefined;
  let appLabel = '';
  let appIcon: string | undefined;
  let theme: string | undefined;
  let launcherActivity: string | undefined;

  const activities: AndroidActivity[] = [];
  const services: AndroidComponent[] = [];
  const receivers: AndroidComponent[] = [];
  const providers: AndroidComponent[] = [];
  const permissions: string[] = [];
  const features: string[] = [];

  // Read manifest root attributes
  for (const attr of root.attributes) {
    if (attr.name === 'package') {
      packageName = String(attr.value);
    } else if (attr.name === 'versionCode' || attr.resId === RES_ATTR_VERSION_CODE) {
      versionCode = Number(attr.value) || 1;
    } else if (attr.name === 'versionName' || attr.resId === RES_ATTR_VERSION_NAME) {
      versionName = String(attr.value);
    }
  }

  // Traverse children
  for (const child of root.children) {
    if (child.tag === 'uses-sdk') {
      for (const attr of child.attributes) {
        if (attr.name === 'minSdkVersion' || attr.resId === RES_ATTR_MIN_SDK) {
          minSdkVersion = Number(attr.value) || 21;
        } else if (attr.name === 'targetSdkVersion' || attr.resId === RES_ATTR_TARGET_SDK) {
          targetSdkVersion = Number(attr.value) || 33;
        } else if (attr.name === 'maxSdkVersion' || attr.resId === RES_ATTR_MAX_SDK) {
          maxSdkVersion = Number(attr.value);
        }
      }
    } else if (child.tag === 'uses-permission') {
      for (const attr of child.attributes) {
        if (attr.name === 'name' || attr.resId === RES_ATTR_NAME) {
          permissions.push(String(attr.value));
        }
      }
    } else if (child.tag === 'uses-feature') {
      for (const attr of child.attributes) {
        if (attr.name === 'name' || attr.resId === RES_ATTR_NAME) {
          features.push(String(attr.value));
        }
      }
    } else if (child.tag === 'application') {
      for (const attr of child.attributes) {
        if (attr.name === 'label' || attr.resId === RES_ATTR_LABEL) {
          appLabel = String(attr.value);
        } else if (attr.name === 'icon' || attr.resId === RES_ATTR_ICON) {
          appIcon = String(attr.value);
        } else if (attr.name === 'theme' || attr.resId === RES_ATTR_THEME) {
          theme = String(attr.value);
        }
      }

      for (const appChild of child.children) {
        if (appChild.tag === 'activity') {
          let actName = '';
          let isLauncher = false;
          let exported = false;
          let label = '';

          for (const attr of appChild.attributes) {
            if (attr.name === 'name' || attr.resId === RES_ATTR_NAME) {
              actName = String(attr.value);
            } else if (attr.name === 'exported' || attr.resId === RES_ATTR_EXPORTED) {
              exported = Boolean(attr.value);
            } else if (attr.name === 'label' || attr.resId === RES_ATTR_LABEL) {
              label = String(attr.value);
            }
          }

          // Check intent-filters for MAIN + LAUNCHER
          for (const filter of appChild.children) {
            if (filter.tag === 'intent-filter') {
              let hasMain = false;
              let hasLauncher = false;

              for (const filterChild of filter.children) {
                if (filterChild.tag === 'action') {
                  const actAttr = filterChild.attributes.find(a => a.name === 'name' || a.resId === RES_ATTR_NAME);
                  if (actAttr && (actAttr.value === 'android.intent.action.MAIN' || actAttr.value === 'MAIN')) {
                    hasMain = true;
                  }
                } else if (filterChild.tag === 'category') {
                  const catAttr = filterChild.attributes.find(a => a.name === 'name' || a.resId === RES_ATTR_NAME);
                  if (catAttr && (catAttr.value === 'android.intent.category.LAUNCHER' || catAttr.value === 'LAUNCHER')) {
                    hasLauncher = true;
                  }
                }
              }

              if (hasMain && hasLauncher) {
                isLauncher = true;
                if (!launcherActivity) {
                  launcherActivity = actName;
                }
              }
            }
          }

          // Normalize relative activity names (e.g. .MainActivity -> com.example.MainActivity)
          if (actName.startsWith('.')) {
            actName = packageName + actName;
          } else if (!actName.includes('.')) {
            actName = packageName + '.' + actName;
          }

          activities.push({
            name: actName,
            isLauncher,
            exported,
            label,
          });
        } else if (appChild.tag === 'service') {
          const nameAttr = appChild.attributes.find(a => a.name === 'name' || a.resId === RES_ATTR_NAME);
          if (nameAttr) services.push({ name: String(nameAttr.value) });
        } else if (appChild.tag === 'receiver') {
          const nameAttr = appChild.attributes.find(a => a.name === 'name' || a.resId === RES_ATTR_NAME);
          if (nameAttr) receivers.push({ name: String(nameAttr.value) });
        } else if (appChild.tag === 'provider') {
          const nameAttr = appChild.attributes.find(a => a.name === 'name' || a.resId === RES_ATTR_NAME);
          if (nameAttr) providers.push({ name: String(nameAttr.value) });
        }
      }
    }
  }

  if (!appLabel && packageName) {
    const parts = packageName.split('.');
    appLabel = parts[parts.length - 1];
    appLabel = appLabel.charAt(0).toUpperCase() + appLabel.slice(1);
  }

  if (!launcherActivity && activities.length > 0) {
    launcherActivity = activities[0].name;
    activities[0].isLauncher = true;
  }

  const rawXml = formatElementAsXml(root, 0);

  return {
    packageName: packageName || 'unknown.package',
    versionCode,
    versionName,
    minSdkVersion,
    targetSdkVersion,
    maxSdkVersion,
    appLabel: appLabel || 'Android Application',
    appIcon,
    theme,
    launcherActivity,
    activities,
    services,
    receivers,
    providers,
    permissions,
    features,
    rawXml,
  };
}

function formatElementAsXml(elem: ParsedElement, indentLevel: number): string {
  const indent = '  '.repeat(indentLevel);
  let attrs = elem.attributes
    .map(a => `${a.name}="${escapeXml(String(a.value))}"`)
    .join(' ');
  if (attrs) attrs = ' ' + attrs;

  if (elem.children.length === 0) {
    return `${indent}<${elem.tag}${attrs} />\n`;
  }

  let result = `${indent}<${elem.tag}${attrs}>\n`;
  for (const child of elem.children) {
    result += formatElementAsXml(child, indentLevel + 1);
  }
  result += `${indent}</${elem.tag}>\n`;
  return result;
}

function escapeXml(unsafe: string): string {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function parsePlainTextManifest(xmlText: string): AndroidManifestData {
  const pkgMatch = xmlText.match(/package\s*=\s*["']([^"']+)["']/i);
  const vCodeMatch = xmlText.match(/versionCode\s*=\s*["'](\d+)["']/i);
  const vNameMatch = xmlText.match(/versionName\s*=\s*["']([^"']+)["']/i);
  const minSdkMatch = xmlText.match(/minSdkVersion\s*=\s*["'](\d+)["']/i);
  const targetSdkMatch = xmlText.match(/targetSdkVersion\s*=\s*["'](\d+)["']/i);
  const labelMatch = xmlText.match(/android:label\s*=\s*["']([^"']+)["']/i);

  const packageName = pkgMatch ? pkgMatch[1] : 'com.example.app';
  const activities: AndroidActivity[] = [];
  const actRegex = /<activity[^>]*android:name\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = actRegex.exec(xmlText)) !== null) {
    let actName = m[1];
    if (actName.startsWith('.')) actName = packageName + actName;
    activities.push({
      name: actName,
      isLauncher: xmlText.includes('android.intent.category.LAUNCHER'),
    });
  }

  const permissions: string[] = [];
  const permRegex = /<uses-permission[^>]*android:name\s*=\s*["']([^"']+)["'][^>]*\/>/gi;
  while ((m = permRegex.exec(xmlText)) !== null) {
    permissions.push(m[1]);
  }

  return {
    packageName,
    versionCode: vCodeMatch ? parseInt(vCodeMatch[1], 10) : 1,
    versionName: vNameMatch ? vNameMatch[1] : '1.0',
    minSdkVersion: minSdkMatch ? parseInt(minSdkMatch[1], 10) : 21,
    targetSdkVersion: targetSdkMatch ? parseInt(targetSdkMatch[1], 10) : 33,
    appLabel: labelMatch ? labelMatch[1] : packageName,
    launcherActivity: activities[0]?.name,
    activities,
    services: [],
    receivers: [],
    providers: [],
    permissions,
    features: [],
    rawXml: xmlText,
  };
}
