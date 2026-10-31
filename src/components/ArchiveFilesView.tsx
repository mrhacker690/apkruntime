/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Archive Files Explorer
 * Tabular inspection of extracted ZIP entries, compression methods, sizes, and CRC32 digests.
 */

import React, { useState } from 'react';
import { ApkArchive } from '../runtime/core/types';
import { FolderArchive, Search, File, FileCode, Image, FileText } from 'lucide-react';

interface ArchiveFilesViewProps {
  archive: ApkArchive;
}

export const ArchiveFilesView: React.FC<ArchiveFilesViewProps> = ({ archive }) => {
  const [search, setSearch] = useState('');

  const filteredEntries = archive.entries.filter(e =>
    e.filename.toLowerCase().includes(search.toLowerCase())
  );

  const totalUncompressed = archive.entries.reduce((acc, e) => acc + e.uncompressedSize, 0);

  const getFileIcon = (filename: string) => {
    if (filename.endsWith('.dex')) return <FileCode className="w-4 h-4 text-indigo-500 shrink-0" />;
    if (filename.endsWith('.xml')) return <FileCode className="w-4 h-4 text-cyan-500 shrink-0" />;
    if (filename.endsWith('.png') || filename.endsWith('.webp') || filename.endsWith('.jpg')) {
      return <Image className="w-4 h-4 text-emerald-500 shrink-0" />;
    }
    if (filename.endsWith('.so')) return <File className="w-4 h-4 text-amber-500 shrink-0" />;
    return <FileText className="w-4 h-4 text-slate-400 shrink-0" />;
  };

  return (
    <div className="space-y-6">
      {/* Top Stats Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
          <div className="text-[11px] font-medium text-slate-500">Total Entries</div>
          <div className="text-xl font-bold text-slate-900 dark:text-white font-mono tabular-nums">
            {archive.entries.length}
          </div>
        </div>
        <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
          <div className="text-[11px] font-medium text-slate-500">Archive Size</div>
          <div className="text-xl font-bold text-slate-900 dark:text-white font-mono tabular-nums">
            {(archive.fileSize / 1024).toFixed(1)} KB
          </div>
        </div>
        <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
          <div className="text-[11px] font-medium text-slate-500">Uncompressed Size</div>
          <div className="text-xl font-bold text-slate-900 dark:text-white font-mono tabular-nums">
            {(totalUncompressed / 1024).toFixed(1)} KB
          </div>
        </div>
        <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
          <div className="text-[11px] font-medium text-slate-500">Compression Method</div>
          <div className="text-xl font-bold text-slate-900 dark:text-white font-mono">
            ZIP Deflate / Stored
          </div>
        </div>
      </div>

      {/* Table Container */}
      <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-100 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <FolderArchive className="w-4 h-4 text-indigo-500" />
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">
              Archive File Manifest ({archive.entries.length} entries)
            </h3>
          </div>

          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search archive files..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-white font-mono focus:outline-none focus:ring-1 focus:ring-indigo-500"
            />
          </div>
        </div>

        <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-slate-50 dark:bg-slate-950/60 border-b border-slate-200 dark:border-slate-800 text-slate-500 sticky top-0 z-10">
              <tr>
                <th className="py-2.5 px-4 font-semibold">Path</th>
                <th className="py-2.5 px-4 font-semibold">Method</th>
                <th className="py-2.5 px-4 font-semibold text-right">Compressed</th>
                <th className="py-2.5 px-4 font-semibold text-right">Uncompressed</th>
                <th className="py-2.5 px-4 font-semibold text-right">CRC-32</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {filteredEntries.map((entry, idx) => (
                <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-slate-950/40">
                  <td className="py-2.5 px-4 text-slate-900 dark:text-slate-200 flex items-center gap-2">
                    {getFileIcon(entry.filename)}
                    <span className="truncate">{entry.filename}</span>
                  </td>
                  <td className="py-2.5 px-4 text-slate-500">
                    {entry.compressionMethod === 8 ? 'Deflated (8)' : 'Stored (0)'}
                  </td>
                  <td className="py-2.5 px-4 text-right tabular-nums text-slate-600 dark:text-slate-400">
                    {(entry.compressedSize / 1024).toFixed(1)} KB
                  </td>
                  <td className="py-2.5 px-4 text-right tabular-nums font-semibold text-slate-900 dark:text-white">
                    {(entry.uncompressedSize / 1024).toFixed(1)} KB
                  </td>
                  <td className="py-2.5 px-4 text-right tabular-nums text-slate-500">
                    0x{entry.crc32.toString(16).padStart(8, '0')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
