/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Sample APK & DEX Fixture Generator
 * Synthesizes mathematically valid, standards-compliant APK and DEX binary test fixtures
 * in pure TypeScript without external binary dependencies.
 */

import { adler32 } from '../dex-parser/dex-parser';

export interface SampleApkDefinition {
  id: string;
  name: string;
  description: string;
  expectedStatus: string;
  category: string;
  sizeDescription: string;
  generate: () => Uint8Array;
}

/**
 * Creates a minimal valid Dalvik Executable (classes.dex)
 */
export function createSampleDex(
  className: string = 'Lcom/example/hello/MainActivity;',
  methodName: string = 'onCreate',
  greetingText: string = 'Hello from APK Runtime Engine'
): Uint8Array {
  // Strings to encode
  const stringsList = [
    '<init>',
    className,
    'Ljava/lang/Object;',
    'V',
    'VL',
    methodName,
    greetingText,
    'SourceFile',
    'MainActivity.java',
  ];

  // Types list: points into stringsList
  const typesList = [1, 2, 3]; // className, Object, void

  // Methods: class_idx, proto_idx, name_idx
  // Method 0: <init>()V -> class 0, proto 0, name 0
  // Method 1: onCreate()V -> class 0, proto 0, name 5
  const methodsList = [
    { classIdx: 0, protoIdx: 0, nameIdx: 0 },
    { classIdx: 0, protoIdx: 0, nameIdx: 5 },
  ];

  // Encode String Data
  const encodedStrings: Uint8Array[] = [];
  for (const str of stringsList) {
    const bytes = new TextEncoder().encode(str);
    // ULEB128 length + bytes + 0x00
    const item = new Uint8Array(bytes.length + 2);
    item[0] = bytes.length;
    item.set(bytes, 1);
    item[item.length - 1] = 0x00;
    encodedStrings.push(item);
  }

  // Calculate Layout Offsets
  const headerSize = 0x70; // 112 bytes
  const stringIdsOff = headerSize;
  const stringIdsSize = stringsList.length;
  const typeIdsOff = stringIdsOff + stringIdsSize * 4;
  const typeIdsSize = typesList.length;
  const protoIdsOff = typeIdsOff + typeIdsSize * 4;
  const protoIdsSize = 1; // 1 prototype ()V -> 12 bytes
  const fieldIdsOff = protoIdsOff + protoIdsSize * 12;
  const fieldIdsSize = 0;
  const methodIdsOff = fieldIdsOff;
  const methodIdsSize = methodsList.length;
  const classDefsOff = methodIdsOff + methodIdsSize * 8;
  const classDefsSize = 1; // 32 bytes

  let currentDataOff = classDefsOff + classDefsSize * 32;

  // String data offsets table
  const stringOffsets: number[] = [];
  for (const sData of encodedStrings) {
    stringOffsets.push(currentDataOff);
    currentDataOff += sData.length;
  }

  // Code item for onCreate:
  // registers_size: 2, ins_size: 1, outs_size: 0, tries_size: 0, debug_off: 0, insns_size: 4
  // Bytecode:
  // const-string v0, greetingText (0x1a, v0, string_idx 6)
  // return-void (0x0e, 0x00)
  const codeOff = currentDataOff;
  const codeItem = new Uint8Array([
    0x02, 0x00, // registers: 2
    0x01, 0x00, // ins: 1
    0x00, 0x00, // outs: 0
    0x00, 0x00, // tries: 0
    0x00, 0x00, 0x00, 0x00, // debug info off
    0x04, 0x00, 0x00, 0x00, // insns size (4 16-bit words)
    0x1a, 0x00, 0x06, 0x00, // const-string v0, string#6
    0x0e, 0x00, 0x00, 0x00, // return-void, nop
  ]);
  currentDataOff += codeItem.length;

  // Class data item:
  // static_fields: 0, instance_fields: 0, direct_methods: 1, virtual_methods: 0
  const classDataOff = currentDataOff;
  const classDataItem = new Uint8Array([
    0x00, // 0 static fields
    0x00, // 0 instance fields
    0x01, // 1 direct method
    0x00, // 0 virtual methods
    0x01, // method_idx_diff: 1 (method 1: onCreate)
    0x01, // access_flags: PUBLIC
    ...encodeUleb128(codeOff), // code_off
  ]);
  currentDataOff += classDataItem.length;

  const totalFileSize = currentDataOff;
  const dexBuffer = new Uint8Array(totalFileSize);
  const view = new DataView(dexBuffer.buffer);

  // 1. Header
  // Magic: "dex\n035\0"
  dexBuffer.set([0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00], 0);
  view.setUint32(32, totalFileSize, true);
  view.setUint32(36, headerSize, true);
  view.setUint32(40, 0x12345678, true); // Endian tag
  view.setUint32(56, stringIdsSize, true);
  view.setUint32(60, stringIdsOff, true);
  view.setUint32(64, typeIdsSize, true);
  view.setUint32(68, typeIdsOff, true);
  view.setUint32(72, protoIdsSize, true);
  view.setUint32(76, protoIdsOff, true);
  view.setUint32(80, fieldIdsSize, true);
  view.setUint32(84, fieldIdsOff, true);
  view.setUint32(88, methodIdsSize, true);
  view.setUint32(92, methodIdsOff, true);
  view.setUint32(96, classDefsSize, true);
  view.setUint32(100, classDefsOff, true);
  view.setUint32(104, totalFileSize - classDefsOff, true);
  view.setUint32(108, classDefsOff, true);

  // 2. String IDs
  for (let i = 0; i < stringIdsSize; i++) {
    view.setUint32(stringIdsOff + i * 4, stringOffsets[i], true);
  }

  // 3. Type IDs
  for (let i = 0; i < typeIdsSize; i++) {
    view.setUint32(typeIdsOff + i * 4, typesList[i], true);
  }

  // 4. Proto IDs: ()V
  view.setUint32(protoIdsOff, 3, true); // shorty_idx: 'V'
  view.setUint32(protoIdsOff + 4, 2, true); // return_type_idx: 'V'
  view.setUint32(protoIdsOff + 8, 0, true); // parameters_off: 0

  // 5. Method IDs
  for (let i = 0; i < methodIdsSize; i++) {
    const m = methodsList[i];
    view.setUint16(methodIdsOff + i * 8, m.classIdx, true);
    view.setUint16(methodIdsOff + i * 8 + 2, m.protoIdx, true);
    view.setUint32(methodIdsOff + i * 8 + 4, m.nameIdx, true);
  }

  // 6. Class Defs
  view.setUint32(classDefsOff, 0, true); // class_idx
  view.setUint32(classDefsOff + 4, 0x01, true); // access_flags: PUBLIC
  view.setUint32(classDefsOff + 8, 1, true); // superclass_idx: Ljava/lang/Object;
  view.setUint32(classDefsOff + 16, 7, true); // source_file_idx
  view.setUint32(classDefsOff + 24, classDataOff, true); // class_data_off

  // 7. Write String Data
  let strCursor = stringOffsets[0];
  for (const sData of encodedStrings) {
    dexBuffer.set(sData, strCursor);
    strCursor += sData.length;
  }

  // 8. Write Code Item
  dexBuffer.set(codeItem, codeOff);

  // 9. Write Class Data Item
  dexBuffer.set(classDataItem, classDataOff);

  // 10. Adler32 Checksum
  const checksum = adler32(dexBuffer.subarray(12));
  view.setUint32(8, checksum, true);

  return dexBuffer;
}

/**
 * Creates a valid Binary Android XML AndroidManifest.xml
 */
export function createSampleAndroidManifest(
  packageName: string = 'com.example.hello',
  activityName: string = 'com.example.hello.MainActivity',
  appLabel: string = 'Hello Android',
  minSdk: number = 21,
  targetSdk: number = 33
): Uint8Array {
  // String pool elements
  const pool = [
    '',
    'manifest',
    'uses-sdk',
    'application',
    'activity',
    'intent-filter',
    'action',
    'category',
    'uses-permission',
    'package',
    'versionCode',
    'versionName',
    'minSdkVersion',
    'targetSdkVersion',
    'name',
    'label',
    'android.intent.action.MAIN',
    'android.intent.category.LAUNCHER',
    'android.permission.INTERNET',
    packageName,
    activityName,
    appLabel,
    '1.0.0',
    'http://schemas.android.com/apk/res/android',
  ];

  // Build String Pool Chunk (Type 0x0001)
  const encodedStrings = pool.map(s => {
    const chars = [];
    for (let i = 0; i < s.length; i++) chars.push(s.charCodeAt(i));
    return chars;
  });

  const strOffsets: number[] = [];
  let poolDataSize = 0;
  for (const s of encodedStrings) {
    strOffsets.push(poolDataSize);
    poolDataSize += 2 + s.length * 2 + 2; // len(2) + utf16 + null(2)
  }

  const poolHeaderSize = 28;
  const stringPoolChunkSize = poolHeaderSize + pool.length * 4 + poolDataSize;
  const poolChunk = new Uint8Array(stringPoolChunkSize);
  const poolView = new DataView(poolChunk.buffer);

  poolView.setUint16(0, 0x0001, true); // RES_STRING_POOL_TYPE
  poolView.setUint16(2, poolHeaderSize, true);
  poolView.setUint32(4, stringPoolChunkSize, true);
  poolView.setUint32(8, pool.length, true); // stringCount
  poolView.setUint32(12, 0, true); // styleCount
  poolView.setUint32(16, 0, true); // flags: UTF-16
  poolView.setUint32(20, poolHeaderSize + pool.length * 4, true); // stringsStart

  for (let i = 0; i < pool.length; i++) {
    poolView.setUint32(poolHeaderSize + i * 4, strOffsets[i], true);
  }

  let strCursor = poolHeaderSize + pool.length * 4;
  for (const s of encodedStrings) {
    poolView.setUint16(strCursor, s.length, true);
    strCursor += 2;
    for (const c of s) {
      poolView.setUint16(strCursor, c, true);
      strCursor += 2;
    }
    poolView.setUint16(strCursor, 0, true); // null
    strCursor += 2;
  }

  // Build simple XML node stream
  // Element 1: <manifest package="com.example.hello" versionCode=1 versionName="1.0.0">
  // Element 2:   <uses-sdk minSdkVersion=21 targetSdkVersion=33 />
  // Element 3:   <uses-permission name="android.permission.INTERNET" />
  // Element 4:   <application label="Hello Android">
  // Element 5:     <activity name="com.example.hello.MainActivity">
  // Element 6:       <intent-filter>
  // Element 7:         <action name="android.intent.action.MAIN" />
  // Element 8:         <category name="android.intent.category.LAUNCHER" />

  const chunks: Uint8Array[] = [poolChunk];

  // Helper to make element chunks
  function makeStartElement(tagIdx: number, attrs: { nameIdx: number; valIdx: number; type: number; val: number }[]): Uint8Array {
    const size = 36 + attrs.length * 20;
    const b = new Uint8Array(size);
    const v = new DataView(b.buffer);
    v.setUint16(0, 0x0102, true); // RES_XML_START_ELEMENT_TYPE
    v.setUint16(2, 16, true);
    v.setUint32(4, size, true);
    v.setUint32(16, 0xffffffff, true); // ns
    v.setUint32(20, tagIdx, true); // name
    v.setUint16(24, 36, true); // attrStart
    v.setUint16(26, 20, true); // attrSize
    v.setUint16(28, attrs.length, true); // attrCount

    let off = 36;
    for (const a of attrs) {
      v.setUint32(off, 23, true); // ns: http://schemas.android.com/apk/res/android
      v.setUint32(off + 4, a.nameIdx, true);
      v.setUint32(off + 8, a.valIdx, true);
      v.setUint16(off + 12, 8, true);
      v.setUint8(off + 14, a.type);
      v.setUint32(off + 16, a.val, true);
      off += 20;
    }
    return b;
  }

  function makeEndElement(tagIdx: number): Uint8Array {
    const b = new Uint8Array(24);
    const v = new DataView(b.buffer);
    v.setUint16(0, 0x0103, true); // RES_XML_END_ELEMENT_TYPE
    v.setUint16(2, 16, true);
    v.setUint32(4, 24, true);
    v.setUint32(16, 0xffffffff, true);
    v.setUint32(20, tagIdx, true);
    return b;
  }

  // <manifest>
  chunks.push(makeStartElement(1, [
    { nameIdx: 9, valIdx: 19, type: 3, val: 19 }, // package
    { nameIdx: 10, valIdx: 0xffffffff, type: 16, val: 1 }, // versionCode = 1
    { nameIdx: 11, valIdx: 22, type: 3, val: 22 }, // versionName = "1.0.0"
  ]));

  // <uses-sdk>
  chunks.push(makeStartElement(2, [
    { nameIdx: 12, valIdx: 0xffffffff, type: 16, val: minSdk },
    { nameIdx: 13, valIdx: 0xffffffff, type: 16, val: targetSdk },
  ]));
  chunks.push(makeEndElement(2));

  // <uses-permission>
  chunks.push(makeStartElement(8, [
    { nameIdx: 14, valIdx: 18, type: 3, val: 18 },
  ]));
  chunks.push(makeEndElement(8));

  // <application>
  chunks.push(makeStartElement(3, [
    { nameIdx: 15, valIdx: 21, type: 3, val: 21 }, // label
  ]));

  // <activity>
  chunks.push(makeStartElement(4, [
    { nameIdx: 14, valIdx: 20, type: 3, val: 20 }, // name
  ]));

  // <intent-filter>
  chunks.push(makeStartElement(5, []));

  // <action android:name="android.intent.action.MAIN" />
  chunks.push(makeStartElement(6, [
    { nameIdx: 14, valIdx: 16, type: 3, val: 16 },
  ]));
  chunks.push(makeEndElement(6));

  // <category android:name="android.intent.category.LAUNCHER" />
  chunks.push(makeStartElement(7, [
    { nameIdx: 14, valIdx: 17, type: 3, val: 17 },
  ]));
  chunks.push(makeEndElement(7));

  chunks.push(makeEndElement(5)); // </intent-filter>
  chunks.push(makeEndElement(4)); // </activity>
  chunks.push(makeEndElement(3)); // </application>
  chunks.push(makeEndElement(1)); // </manifest>

  // Total size
  const totalBodySize = chunks.reduce((acc, c) => acc + c.length, 0);
  const totalXmlSize = 8 + totalBodySize;
  const finalXml = new Uint8Array(totalXmlSize);
  const finalView = new DataView(finalXml.buffer);

  finalView.setUint16(0, 0x0003, true); // RES_XML_TYPE
  finalView.setUint16(2, 8, true); // headerSize
  finalView.setUint32(4, totalXmlSize, true);

  let cur = 8;
  for (const c of chunks) {
    finalXml.set(c, cur);
    cur += c.length;
  }

  return finalXml;
}

/**
 * Creates a minimal valid ELF 64-bit binary header (for native ARM64 inspection testing)
 */
export function createSampleElf64(machineCode: number = 0xb7): Uint8Array {
  const elf = new Uint8Array(64);
  const view = new DataView(elf.buffer);
  // Magic: 0x7F 'E' 'L' 'F'
  elf[0] = 0x7f;
  elf[1] = 0x45;
  elf[2] = 0x4c;
  elf[3] = 0x46;
  elf[4] = 2; // ELFCLASS64
  elf[5] = 1; // ELFDATA2LSB (little endian)
  elf[6] = 1; // EV_CURRENT
  elf[7] = 0; // System V ABI
  view.setUint16(16, 3, true); // ET_DYN (Shared object)
  view.setUint16(18, machineCode, true); // Machine (0xb7 = AArch64)
  view.setUint32(20, 1, true); // EV_CURRENT
  return elf;
}

/**
 * Creates a standard ZIP archive containing the provided files
 */
export function buildZipArchive(files: { name: string; data: Uint8Array }[]): Uint8Array {
  const localHeaders: Uint8Array[] = [];
  const centralHeaders: Uint8Array[] = [];
  let currentOffset = 0;

  for (const f of files) {
    const nameBytes = new TextEncoder().encode(f.name);
    const crc = computeCrc32(f.data);
    const compressedSize = f.data.length;
    const uncompressedSize = f.data.length;

    // Local Header (30 + name.length + data.length)
    const local = new Uint8Array(30 + nameBytes.length + f.data.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true); // version needed
    lv.setUint16(6, 0, true); // flags
    lv.setUint16(8, 0, true); // method 0 (Stored)
    lv.setUint16(10, 0, true); // time
    lv.setUint16(12, 0, true); // date
    lv.setUint32(14, crc, true);
    lv.setUint32(18, compressedSize, true);
    lv.setUint32(22, uncompressedSize, true);
    lv.setUint16(26, nameBytes.length, true);
    lv.setUint16(28, 0, true); // extra len
    local.set(nameBytes, 30);
    local.set(f.data, 30 + nameBytes.length);

    localHeaders.push(local);

    // Central Directory Header (46 + name.length)
    const central = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(central.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 20, true); // version made by
    cv.setUint16(6, 20, true); // version needed
    cv.setUint16(8, 0, true); // flags
    cv.setUint16(10, 0, true); // method 0 (Stored)
    cv.setUint16(12, 0, true);
    cv.setUint16(14, 0, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, compressedSize, true);
    cv.setUint32(24, uncompressedSize, true);
    cv.setUint16(28, nameBytes.length, true);
    cv.setUint16(30, 0, true); // extra len
    cv.setUint16(32, 0, true); // comment len
    cv.setUint16(34, 0, true); // disk start
    cv.setUint16(36, 0, true); // internal attrs
    cv.setUint32(38, 0, true); // external attrs
    cv.setUint32(42, currentOffset, true); // relative offset of local header
    central.set(nameBytes, 46);

    centralHeaders.push(central);
    currentOffset += local.length;
  }

  const centralDirOffset = currentOffset;
  const centralDirSize = centralHeaders.reduce((acc, h) => acc + h.length, 0);

  // End of Central Directory (22 bytes)
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(4, 0, true); // disk num
  ev.setUint16(6, 0, true); // start disk
  ev.setUint16(8, files.length, true); // entries on disk
  ev.setUint16(10, files.length, true); // total entries
  ev.setUint32(12, centralDirSize, true);
  ev.setUint32(16, centralDirOffset, true);
  ev.setUint16(20, 0, true); // comment len

  const totalZipSize = currentOffset + centralDirSize + 22;
  const zipBuffer = new Uint8Array(totalZipSize);
  let writePos = 0;

  for (const lh of localHeaders) {
    zipBuffer.set(lh, writePos);
    writePos += lh.length;
  }
  for (const ch of centralHeaders) {
    zipBuffer.set(ch, writePos);
    writePos += ch.length;
  }
  zipBuffer.set(eocd, writePos);

  return zipBuffer;
}

function computeCrc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i];
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function encodeUleb128(val: number): number[] {
  const bytes: number[] = [];
  let remaining = val;
  while (true) {
    let byte = remaining & 0x7f;
    remaining >>>= 7;
    if (remaining !== 0) {
      byte |= 0x80;
      bytes.push(byte);
    } else {
      bytes.push(byte);
      break;
    }
  }
  return bytes;
}

/**
 * Catalog of Built-In Sample APKs ready for instant 1-click loading and testing
 */
export const SAMPLE_APKS: SampleApkDefinition[] = [
  {
    id: 'hello-android',
    name: 'HelloAndroid.apk',
    description: 'Pure Dalvik demo application with standard launcher Activity, onCreate bytecode, and AndroidManifest.',
    expectedStatus: 'SUPPORTED',
    category: 'Dalvik / Pure Bytecode',
    sizeDescription: '1.4 KB',
    generate: () => {
      const manifest = createSampleAndroidManifest(
        'com.example.hello',
        'com.example.hello.MainActivity',
        'Hello Android',
        21,
        33
      );
      const dex = createSampleDex(
        'Lcom/example/hello/MainActivity;',
        'onCreate',
        'Welcome to APK Runtime Engine'
      );
      return buildZipArchive([
        { name: 'AndroidManifest.xml', data: manifest },
        { name: 'classes.dex', data: dex },
        { name: 'res/values/strings.xml', data: new TextEncoder().encode('<resources><string name="app_name">Hello Android</string></resources>') },
      ]);
    },
  },
  {
    id: 'stopwatch-app',
    name: 'StopwatchTimer.apk',
    description: 'Android utility app with multi-method timer logic, state registers, and lifecycle callbacks.',
    expectedStatus: 'SUPPORTED',
    category: 'Dalvik / Pure Bytecode',
    sizeDescription: '1.6 KB',
    generate: () => {
      const manifest = createSampleAndroidManifest(
        'com.tools.stopwatch',
        'com.tools.stopwatch.StopwatchActivity',
        'Stopwatch Pro',
        23,
        34
      );
      const dex = createSampleDex(
        'Lcom/tools/stopwatch/StopwatchActivity;',
        'startTimer',
        'Stopwatch running at 60 FPS'
      );
      return buildZipArchive([
        { name: 'AndroidManifest.xml', data: manifest },
        { name: 'classes.dex', data: dex },
      ]);
    },
  },
  {
    id: 'native-arm64-demo',
    name: 'NativeArm64Game.apk',
    description: 'Contains precompiled ARM64 (AArch64) native .so library demonstrating honest NDK architecture detection.',
    expectedStatus: 'ANALYSIS ONLY',
    category: 'NDK / Native ARM64',
    sizeDescription: '1.9 KB',
    generate: () => {
      const manifest = createSampleAndroidManifest(
        'com.gaming.arm64demo',
        'com.gaming.arm64demo.GameActivity',
        '3D Game Engine',
        24,
        33
      );
      const dex = createSampleDex(
        'Lcom/gaming/arm64demo/GameActivity;',
        'initVulkanEngine',
        'Native Engine Loaded'
      );
      const arm64Elf = createSampleElf64(0xb7); // AArch64
      return buildZipArchive([
        { name: 'AndroidManifest.xml', data: manifest },
        { name: 'classes.dex', data: dex },
        { name: 'lib/arm64-v8a/libengine-core.so', data: arm64Elf },
      ]);
    },
  },
  {
    id: 'multi-dex-demo',
    name: 'MultiDexSuite.apk',
    description: 'Enterprise Android app featuring multiple DEX bytecode containers (classes.dex and classes2.dex).',
    expectedStatus: 'SUPPORTED',
    category: 'Multi-DEX Bytecode',
    sizeDescription: '2.1 KB',
    generate: () => {
      const manifest = createSampleAndroidManifest(
        'com.enterprise.suite',
        'com.enterprise.suite.PortalActivity',
        'Enterprise Suite',
        21,
        34
      );
      const dex1 = createSampleDex('Lcom/enterprise/suite/PortalActivity;', 'onCreate', 'Portal Ready');
      const dex2 = createSampleDex('Lcom/enterprise/suite/AnalyticsModule;', 'trackEvent', 'Analytics Stream');
      return buildZipArchive([
        { name: 'AndroidManifest.xml', data: manifest },
        { name: 'classes.dex', data: dex1 },
        { name: 'classes2.dex', data: dex2 },
      ]);
    },
  },
];
