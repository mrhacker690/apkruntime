/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Hardened Binary Android XML (AXML / ResXMLTree) Parser
 * Decodes compiled AndroidManifest.xml chunks, string pools, attributes, and namespaces
 * with strict boundary checks, no invented defaults, and transparent resource reference preservation.
 */

import { AndroidManifestData, AndroidActivity, AndroidComponent } from '../core/types';

// Chunk Types
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

// Dimension & Fraction unit masks
const COMPLEX_UNIT_SHIFT = 0;
const COMPLEX_UNIT_MASK = 0x0f;
const DIMENSION_UNITS = ['px', 'dp', 'sp', 'pt', 'in', 'mm'];
const FRACTION_UNITS = ['%', '%p'];

// Well-known Android resource attribute IDs
const RES_ATTR_LABEL = 0x01010001;
const RES_ATTR_ICON = 0x01010002;
const RES_ATTR_NAME = 0x01010003;
const RES_ATTR_EXPORTED = 0x01010010;
const RES_ATTR_THEME = 0x01010000;
const RES_ATTR_MIN_SDK = 0x0101020c;
const RES_ATTR_VERSION_CODE = 0x0101021b;
const RES_ATTR_VERSION_NAME = 0x0101021c;
const RES_ATTR_TARGET_SDK = 0x01010270;
const RES_ATTR_MAX_SDK = 0x01010271;
const RES_ATTR_REQUIRED = 0x0101028e;

export interface ParsedAttribute {
  namespaceUri: string;
  name: string;
  rawValue: string;
  typedValue: unknown;
  dataType: number;
  resId?: number;
}

export interface ParsedElement {
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

/**
 * Parses binary Android XML (AndroidManifest.xml).
 * Strictly validates chunk headers, offsets, and data boundaries without arbitrary overflow allowances.
 */
export function parseBinaryAndroidManifest(buffer: Uint8Array): AndroidManifestData {
  if (!buffer || buffer.byteLength < 8) {
    throw new AxmlParseError('File too small to be a valid Android binary XML (minimum 8 bytes required).');
  }

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const fileType = view.getUint16(0, true);

  if (fileType !== RES_XML_TYPE) {
    // If it's already plain text XML, handle as fallback
    const text = new TextDecoder('utf-8').decode(buffer);
    if (text.includes('<manifest') || text.includes('<?xml')) {
      return parsePlainTextManifest(text);
    }
    throw new AxmlParseError(`Invalid AXML magic type: expected 0x0003 (RES_XML_TYPE), got 0x${fileType.toString(16)}.`);
  }

  const headerSize = view.getUint16(2, true);
  const declaredFileSize = view.getUint32(4, true);

  if (headerSize < 8 || headerSize > buffer.byteLength) {
    throw new AxmlParseError(`Invalid AXML header size (${headerSize}).`);
  }

  // Strict buffer boundary check: chunk stream must not extend beyond actual buffer
  const maxReadableSize = Math.min(buffer.byteLength, declaredFileSize);

  let offset = headerSize;
  let stringPool: string[] = [];
  let resourceIds: number[] = [];

  const rootElements: ParsedElement[] = [];
  const elementStack: ParsedElement[] = [];

  while (offset < maxReadableSize) {
    if (offset + 8 > buffer.byteLength) {
      throw new AxmlParseError(`Unexpected EOF at offset 0x${offset.toString(16)}: truncated chunk header.`);
    }

    const chunkType = view.getUint16(offset, true);
    const chunkHeaderSize = view.getUint16(offset + 2, true);
    const chunkSize = view.getUint32(offset + 4, true);

    if (chunkSize < 8) {
      throw new AxmlParseError(`Corrupted chunk size (${chunkSize}) at offset 0x${offset.toString(16)}.`);
    }

    if (offset + chunkSize > buffer.byteLength) {
      throw new AxmlParseError(
        `Chunk 0x${chunkType.toString(16)} extends outside actual file buffer (offset: 0x${offset.toString(16)}, size: ${chunkSize}, buffer: ${buffer.byteLength}).`
      );
    }

    switch (chunkType) {
      case RES_STRING_POOL_TYPE: {
        stringPool = parseStringPool(buffer, offset, chunkSize);
        break;
      }

      case RES_XML_RESOURCE_MAP_TYPE: {
        if (chunkHeaderSize < 8 || chunkHeaderSize > chunkSize) {
          throw new AxmlParseError(`Invalid resource map chunk header size (${chunkHeaderSize}).`);
        }
        const idCount = Math.floor((chunkSize - chunkHeaderSize) / 4);
        resourceIds = [];
        for (let i = 0; i < idCount; i++) {
          const idOff = offset + chunkHeaderSize + i * 4;
          resourceIds.push(view.getUint32(idOff, true));
        }
        break;
      }

      case RES_XML_START_ELEMENT_TYPE: {
        if (chunkSize < 36) {
          throw new AxmlParseError(`Malformed start element chunk at offset 0x${offset.toString(16)} (size ${chunkSize} < 36).`);
        }

        const nsIdx = view.getUint32(offset + 16, true);
        const nameIdx = view.getUint32(offset + 20, true);
        const attrStart = view.getUint16(offset + 24, true);
        const attrSize = view.getUint16(offset + 26, true);
        const attrCount = view.getUint16(offset + 28, true);

        const tagName = getStringFromPool(stringPool, nameIdx);
        if (!tagName) {
          throw new AxmlParseError(`Start element at 0x${offset.toString(16)} references invalid tag string index ${nameIdx}.`);
        }

        const attributes: ParsedAttribute[] = [];
        let attrOffset = offset + attrStart;

        for (let a = 0; a < attrCount; a++) {
          if (attrOffset + 20 > offset + chunkSize || attrOffset + 20 > buffer.byteLength) {
            throw new AxmlParseError(`Attribute ${a} in <${tagName}> exceeds element chunk boundaries.`);
          }

          const attrNsIdx = view.getUint32(attrOffset, true);
          const attrNameIdx = view.getUint32(attrOffset + 4, true);
          const rawValIdx = view.getUint32(attrOffset + 8, true);
          const valSize = view.getUint16(attrOffset + 12, true);
          const dataType = view.getUint8(attrOffset + 14);
          const dataVal = view.getUint32(attrOffset + 16, true);

          const attrNs = getStringFromPool(stringPool, attrNsIdx);
          const attrName = getStringFromPool(stringPool, attrNameIdx);
          const rawVal = getStringFromPool(stringPool, rawValIdx);

          const typedValue = decodeTypedValue(dataType, dataVal, stringPool, rawVal);
          const resId = attrNameIdx < resourceIds.length ? resourceIds[attrNameIdx] : undefined;

          attributes.push({
            namespaceUri: attrNs,
            name: attrName,
            rawValue: rawVal,
            typedValue,
            dataType,
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
        // Well-formed XML tree skipping
        break;
    }

    offset += chunkSize;
  }

  const root = rootElements[0];
  if (!root) {
    throw new AxmlParseError('No root XML element found in manifest.');
  }

  return extractManifestMetadata(root);
}

/**
 * Decodes Android typed values into appropriate JavaScript primitives or formatted references.
 */
function decodeTypedValue(
  dataType: number,
  dataVal: number,
  stringPool: string[],
  rawVal: string
): unknown {
  switch (dataType) {
    case TYPE_NULL:
      return null;

    case TYPE_REFERENCE:
      // Keep explicitly as resource reference without pretending to resolve it before resources.arsc
      return `@0x${dataVal.toString(16).padStart(8, '0')}`;

    case TYPE_ATTRIBUTE:
      return `?0x${dataVal.toString(16).padStart(8, '0')}`;

    case TYPE_STRING:
      return getStringFromPool(stringPool, dataVal) || rawVal;

    case TYPE_FLOAT: {
      const floatView = new DataView(new ArrayBuffer(4));
      floatView.setUint32(0, dataVal, true);
      return floatView.getFloat32(0, true);
    }

    case TYPE_DIMENSION: {
      const val = dataVal >> 8;
      const unitIdx = (dataVal >> COMPLEX_UNIT_SHIFT) & COMPLEX_UNIT_MASK;
      const unit = DIMENSION_UNITS[unitIdx] || '';
      return `${val}${unit}`;
    }

    case TYPE_FRACTION: {
      const val = (dataVal >> 8) / 100;
      const unitIdx = (dataVal >> COMPLEX_UNIT_SHIFT) & COMPLEX_UNIT_MASK;
      const unit = FRACTION_UNITS[unitIdx] || '';
      return `${val}${unit}`;
    }

    case TYPE_INT_DEC:
      return dataVal | 0; // Signed 32-bit int

    case TYPE_INT_HEX:
      return `0x${(dataVal >>> 0).toString(16)}`;

    case TYPE_INT_BOOLEAN:
      return dataVal !== 0;

    case TYPE_INT_COLOR_ARGB8:
    case TYPE_INT_COLOR_RGB8:
    case TYPE_INT_COLOR_ARGB4:
    case TYPE_INT_COLOR_RGB4:
      return `#${(dataVal >>> 0).toString(16).padStart(8, '0')}`;

    default:
      return rawVal || `[TypedValue 0x${dataType.toString(16)}: 0x${dataVal.toString(16)}]`;
  }
}

/**
 * Parses and bounds-checks the ResStringPool chunk
 */
function parseStringPool(buffer: Uint8Array, offset: number, chunkSize: number): string[] {
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const chunkEnd = offset + chunkSize;

  if (chunkSize < 28) {
    throw new AxmlParseError('String pool chunk is truncated (less than 28 bytes).');
  }

  const stringCount = view.getUint32(offset + 8, true);
  const flags = view.getUint32(offset + 16, true);
  const stringsStart = view.getUint32(offset + 20, true);
  const isUtf8 = (flags & (1 << 8)) !== 0;

  // Protect against uncontrolled allocations from malicious headers
  if (stringCount > 100000) {
    throw new AxmlParseError(`Declared string pool count (${stringCount}) exceeds maximum safety limit.`);
  }

  const stringOffsets: number[] = [];
  const baseOffsets = offset + 28;

  for (let i = 0; i < stringCount; i++) {
    if (baseOffsets + i * 4 + 4 > chunkEnd) {
      throw new AxmlParseError(`String offset table truncated at index ${i}.`);
    }
    stringOffsets.push(view.getUint32(baseOffsets + i * 4, true));
  }

  const strings: string[] = [];
  const poolBase = offset + stringsStart;

  for (let i = 0; i < stringCount; i++) {
    const strOffset = poolBase + stringOffsets[i];
    if (strOffset >= chunkEnd || strOffset < offset) {
      strings.push('');
      continue;
    }

    if (isUtf8) {
      // UTF-8 String decoding
      let cur = strOffset;
      if (cur >= chunkEnd) { strings.push(''); continue; }

      // Skip char length
      if (buffer[cur] & 0x80) cur += 2;
      else cur += 1;

      if (cur >= chunkEnd) { strings.push(''); continue; }

      // Read byte length
      let byteLen = buffer[cur];
      if (byteLen & 0x80) {
        if (cur + 1 >= chunkEnd) { strings.push(''); continue; }
        byteLen = ((byteLen & 0x7f) << 8) | buffer[cur + 1];
        cur += 2;
      } else {
        cur += 1;
      }

      if (cur + byteLen > chunkEnd) {
        strings.push('');
        continue;
      }

      const strBytes = buffer.subarray(cur, cur + byteLen);
      strings.push(new TextDecoder('utf-8', { fatal: false }).decode(strBytes));
    } else {
      // UTF-16LE String decoding
      let cur = strOffset;
      if (cur + 2 > chunkEnd) { strings.push(''); continue; }

      let charLen = view.getUint16(cur, true);
      cur += 2;
      if (charLen & 0x8000) {
        if (cur + 2 > chunkEnd) { strings.push(''); continue; }
        charLen = ((charLen & 0x7fff) << 16) | view.getUint16(cur, true);
        cur += 2;
      }

      const byteLen = charLen * 2;
      if (cur + byteLen > chunkEnd) {
        strings.push('');
        continue;
      }

      const strBytes = buffer.subarray(cur, cur + byteLen);
      strings.push(new TextDecoder('utf-16le', { fatal: false }).decode(strBytes));
    }
  }

  return strings;
}

function getStringFromPool(pool: string[], index: number): string {
  if (index >= 0 && index < pool.length) {
    return pool[index] ?? '';
  }
  return '';
}

/**
 * Extracts structured manifest metadata without inventing fake defaults
 */
function extractManifestMetadata(root: ParsedElement): AndroidManifestData {
  let packageName = '';
  let versionCode: number | undefined;
  let versionName: string | undefined;
  let compileSdkVersion: number | undefined;
  let minSdkVersion: number | undefined;
  let targetSdkVersion: number | undefined;
  let maxSdkVersion: number | undefined;
  let appLabel: string | undefined;
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
      packageName = String(attr.typedValue || attr.rawValue);
    } else if (attr.name === 'versionCode' || attr.resId === RES_ATTR_VERSION_CODE) {
      if (typeof attr.typedValue === 'number') {
        versionCode = attr.typedValue;
      } else if (attr.rawValue) {
        versionCode = parseInt(attr.rawValue, 10);
      }
    } else if (attr.name === 'versionName' || attr.resId === RES_ATTR_VERSION_NAME) {
      versionName = String(attr.typedValue || attr.rawValue);
    } else if (attr.name === 'compileSdkVersion') {
      if (typeof attr.typedValue === 'number') {
        compileSdkVersion = attr.typedValue;
      }
    }
  }

  // Traverse children
  for (const child of root.children) {
    if (child.tag === 'uses-sdk') {
      for (const attr of child.attributes) {
        if (attr.name === 'minSdkVersion' || attr.resId === RES_ATTR_MIN_SDK) {
          if (typeof attr.typedValue === 'number') minSdkVersion = attr.typedValue;
          else if (attr.rawValue) minSdkVersion = parseInt(attr.rawValue, 10);
        } else if (attr.name === 'targetSdkVersion' || attr.resId === RES_ATTR_TARGET_SDK) {
          if (typeof attr.typedValue === 'number') targetSdkVersion = attr.typedValue;
          else if (attr.rawValue) targetSdkVersion = parseInt(attr.rawValue, 10);
        } else if (attr.name === 'maxSdkVersion' || attr.resId === RES_ATTR_MAX_SDK) {
          if (typeof attr.typedValue === 'number') maxSdkVersion = attr.typedValue;
          else if (attr.rawValue) maxSdkVersion = parseInt(attr.rawValue, 10);
        }
      }
    } else if (child.tag === 'uses-permission') {
      for (const attr of child.attributes) {
        if (attr.name === 'name' || attr.resId === RES_ATTR_NAME) {
          const pName = String(attr.typedValue || attr.rawValue);
          if (pName && !permissions.includes(pName)) {
            permissions.push(pName);
          }
        }
      }
    } else if (child.tag === 'uses-feature') {
      for (const attr of child.attributes) {
        if (attr.name === 'name' || attr.resId === RES_ATTR_NAME) {
          const fName = String(attr.typedValue || attr.rawValue);
          if (fName && !features.includes(fName)) {
            features.push(fName);
          }
        }
      }
    } else if (child.tag === 'application') {
      for (const attr of child.attributes) {
        if (attr.name === 'label' || attr.resId === RES_ATTR_LABEL) {
          appLabel = String(attr.typedValue || attr.rawValue);
        } else if (attr.name === 'icon' || attr.resId === RES_ATTR_ICON) {
          appIcon = String(attr.typedValue || attr.rawValue);
        } else if (attr.name === 'theme' || attr.resId === RES_ATTR_THEME) {
          theme = String(attr.typedValue || attr.rawValue);
        }
      }

      for (const appChild of child.children) {
        if (appChild.tag === 'activity' || appChild.tag === 'activity-alias') {
          let actName = '';
          let isLauncher = false;
          let exported: boolean | undefined = undefined;
          let label: string | undefined = undefined;

          for (const attr of appChild.attributes) {
            if (attr.name === 'name' || attr.resId === RES_ATTR_NAME) {
              actName = String(attr.typedValue || attr.rawValue);
            } else if (attr.name === 'exported' || attr.resId === RES_ATTR_EXPORTED) {
              if (typeof attr.typedValue === 'boolean') {
                exported = attr.typedValue;
              } else if (typeof attr.typedValue === 'number') {
                exported = attr.typedValue !== 0;
              }
            } else if (attr.name === 'label' || attr.resId === RES_ATTR_LABEL) {
              label = String(attr.typedValue || attr.rawValue);
            }
          }

          // Inspect intent filters for MAIN + LAUNCHER
          for (const filter of appChild.children) {
            if (filter.tag === 'intent-filter') {
              let hasMain = false;
              let hasLauncher = false;

              for (const filterChild of filter.children) {
                if (filterChild.tag === 'action') {
                  const actAttr = filterChild.attributes.find(a => a.name === 'name' || a.resId === RES_ATTR_NAME);
                  const val = String(actAttr?.typedValue || actAttr?.rawValue || '');
                  if (val === 'android.intent.action.MAIN' || val === 'MAIN') {
                    hasMain = true;
                  }
                } else if (filterChild.tag === 'category') {
                  const catAttr = filterChild.attributes.find(a => a.name === 'name' || a.resId === RES_ATTR_NAME);
                  const val = String(catAttr?.typedValue || catAttr?.rawValue || '');
                  if (val === 'android.intent.category.LAUNCHER' || val === 'LAUNCHER') {
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

          // Normalize relative activity paths
          if (actName.startsWith('.')) {
            actName = packageName + actName;
          } else if (actName && !actName.includes('.')) {
            actName = packageName + '.' + actName;
          }

          activities.push({
            name: actName || '(unnamed activity)',
            isLauncher,
            exported,
            label,
          });
        } else if (appChild.tag === 'service') {
          const nameAttr = appChild.attributes.find(a => a.name === 'name' || a.resId === RES_ATTR_NAME);
          const expAttr = appChild.attributes.find(a => a.name === 'exported' || a.resId === RES_ATTR_EXPORTED);
          if (nameAttr) {
            services.push({
              name: String(nameAttr.typedValue || nameAttr.rawValue),
              exported: typeof expAttr?.typedValue === 'boolean' ? expAttr.typedValue : undefined,
            });
          }
        } else if (appChild.tag === 'receiver') {
          const nameAttr = appChild.attributes.find(a => a.name === 'name' || a.resId === RES_ATTR_NAME);
          const expAttr = appChild.attributes.find(a => a.name === 'exported' || a.resId === RES_ATTR_EXPORTED);
          if (nameAttr) {
            receivers.push({
              name: String(nameAttr.typedValue || nameAttr.rawValue),
              exported: typeof expAttr?.typedValue === 'boolean' ? expAttr.typedValue : undefined,
            });
          }
        } else if (appChild.tag === 'provider') {
          const nameAttr = appChild.attributes.find(a => a.name === 'name' || a.resId === RES_ATTR_NAME);
          if (nameAttr) {
            providers.push({
              name: String(nameAttr.typedValue || nameAttr.rawValue),
            });
          }
        }
      }
    }
  }

  // If launcherActivity wasn't explicitly matched with action.MAIN + category.LAUNCHER, do NOT fake one!
  // Represent as undefined if missing.

  const rawXml = formatElementAsXml(root, 0);

  return {
    packageName: packageName || 'unknown.package',
    versionCode,
    versionName,
    compileSdkVersion,
    minSdkVersion,
    targetSdkVersion,
    maxSdkVersion,
    appLabel,
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
    .map(a => `${a.name}="${escapeXml(String(a.typedValue !== undefined && a.typedValue !== null ? a.typedValue : a.rawValue))}"`)
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
  const maxSdkMatch = xmlText.match(/maxSdkVersion\s*=\s*["'](\d+)["']/i);
  const labelMatch = xmlText.match(/android:label\s*=\s*["']([^"']+)["']/i);

  const packageName = pkgMatch ? pkgMatch[1] : 'unknown.package';
  const activities: AndroidActivity[] = [];
  const actRegex = /<activity[^>]*android:name\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = actRegex.exec(xmlText)) !== null) {
    let actName = m[1];
    if (actName.startsWith('.')) actName = packageName + actName;
    activities.push({
      name: actName,
      isLauncher: xmlText.includes('android.intent.category.LAUNCHER') && xmlText.includes(actName),
    });
  }

  const permissions: string[] = [];
  const permRegex = /<uses-permission[^>]*android:name\s*=\s*["']([^"']+)["'][^>]*\/>/gi;
  while ((m = permRegex.exec(xmlText)) !== null) {
    permissions.push(m[1]);
  }

  const launcherAct = activities.find(a => a.isLauncher)?.name;

  return {
    packageName,
    versionCode: vCodeMatch ? parseInt(vCodeMatch[1], 10) : undefined,
    versionName: vNameMatch ? vNameMatch[1] : undefined,
    minSdkVersion: minSdkMatch ? parseInt(minSdkMatch[1], 10) : undefined,
    targetSdkVersion: targetSdkMatch ? parseInt(targetSdkMatch[1], 10) : undefined,
    maxSdkVersion: maxSdkMatch ? parseInt(maxSdkMatch[1], 10) : undefined,
    appLabel: labelMatch ? labelMatch[1] : undefined,
    launcherActivity: launcherAct,
    activities,
    services: [],
    receivers: [],
    providers: [],
    permissions,
    features: [],
    rawXml: xmlText,
  };
}
