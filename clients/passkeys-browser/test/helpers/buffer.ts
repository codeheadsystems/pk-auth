// SPDX-License-Identifier: MIT
export class BufferUint8 {
  private readonly chunks: Uint8Array[];

  constructor() {
    this.chunks = [];
  }

  uint8array(data: Uint8Array): this {
    this.chunks.push(data);
    return this;
  }

  uint8(value: number): this {
    this.chunks.push(new Uint8Array([value]));
    return this;
  }

  uint16(value: number): this {
    const buf = new Uint8Array(2);
    new DataView(buf.buffer).setUint16(0, value);
    this.chunks.push(buf);
    return this;
  }

  skip(count: number): this {
    this.chunks.push(new Uint8Array(count));
    return this;
  }

  bytes(): Uint8Array {
    const size = this.chunks.reduce((n, c) => n + c.length, 0);
    const out = new Uint8Array(size);
    let off = 0;
    for (const chunk of this.chunks) {
      out.set(chunk, off);
      off += chunk.length;
    }
    return out;
  }
}
