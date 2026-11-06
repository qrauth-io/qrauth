// SPDX-License-Identifier: MIT
// Types for the parts of qrcode@1.5.4's pure core that the renderer uses.
// Only core modules are imported: no fs, canvas or pngjs in this graph.

declare module 'qrcode/lib/core/qrcode.js' {
  interface BitMatrix {
    size: number;
    data: Uint8Array;
    reservedBit: Uint8Array;
  }
  interface QRCodeSymbol {
    modules: BitMatrix;
    version: number;
    maskPattern: number;
  }
  const QRCodeCore: {
    create(text: string, options: { errorCorrectionLevel: 'L' | 'M' | 'Q' | 'H' }): QRCodeSymbol;
  };
  export default QRCodeCore;
}

declare module 'qrcode/lib/core/alignment-pattern.js' {
  const AlignmentPattern: {
    /** Centres as [row, col], finder overlaps excluded. */
    getPositions(version: number): Array<[number, number]>;
  };
  export default AlignmentPattern;
}

declare module 'qrcode/lib/core/error-correction-code.js' {
  const ECCode: {
    getBlocksCount(version: number, ecLevel: { bit: number }): number;
    getTotalCodewordsCount(version: number, ecLevel: { bit: number }): number;
  };
  export default ECCode;
}

declare module 'qrcode/lib/core/error-correction-level.js' {
  const ECLevel: {
    L: { bit: number };
    M: { bit: number };
    Q: { bit: number };
    H: { bit: number };
  };
  export default ECLevel;
}

declare module 'qrcode/lib/core/utils.js' {
  const Utils: { getSymbolTotalCodewords(version: number): number };
  export default Utils;
}
