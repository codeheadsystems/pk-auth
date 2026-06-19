// SPDX-License-Identifier: MIT
import { describe, expect, it } from "vitest";
import { BufferUint8 } from "./buffer";

describe("BufferUint8", () => {
  it("returns empty bytes when nothing is written", () => {
    const buf = new BufferUint8();
    expect(buf.bytes()).toEqual(new Uint8Array(0));
  });

  it("set appends a Uint8Array", () => {
    const buf = new BufferUint8();
    buf.uint8array(new Uint8Array([1, 2, 3]));
    expect(buf.bytes()).toEqual(new Uint8Array([1, 2, 3]));
  });

  it("uint8 appends a single byte", () => {
    const buf = new BufferUint8();
    buf.uint8(0x45);
    expect(buf.bytes()).toEqual(new Uint8Array([0x45]));
  });

  it("uint16 appends two bytes big-endian", () => {
    const buf = new BufferUint8();
    buf.uint16(0x0102);
    expect(buf.bytes()).toEqual(new Uint8Array([0x01, 0x02]));
  });

  it("skip appends zero bytes", () => {
    const buf = new BufferUint8();
    buf.uint8(0xAA).skip(2).uint8(0xBB);
    expect(buf.bytes()).toEqual(new Uint8Array([0xAA, 0x00, 0x00, 0xBB]));
  });

  it("methods are chainable", () => {
    const data = new Uint8Array([10, 20]);
    const result = new BufferUint8()
      .uint8array(data)
      .uint8(0x45)
      .skip(4)
      .uint16(data.length)
      .uint8array(data)
      .bytes();

    expect(result).toEqual(new Uint8Array([10, 20, 0x45, 0, 0, 0, 0, 0, 2, 10, 20]));
  });

  it("bytes() can be called multiple times and returns equal results", () => {
    const buf = new BufferUint8().uint8(1).uint8(2);
    expect(buf.bytes()).toEqual(buf.bytes());
  });
});
