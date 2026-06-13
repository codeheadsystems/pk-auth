// SPDX-License-Identifier: MIT
import { describe, expect, it } from "vitest";
import {HttpServer, decodeJson, encodeJson} from "./httpServer";

describe("Httpserver", () => {
  it("routes a POST request to the matching handler and returns its response", async () => {
    await using server = new HttpServer({
      "/hello": async (req, res) => {
        const body = await decodeJson<{ msg: string }>(req);
        await encodeJson({ echo: body.msg }, res);
      },
    });
    await server.listen();

    const res = await fetch(`${server.url}/hello`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ msg: "world" }),
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ echo: "world" });
  });

  it("returns 404 for an unregistered path", async () => {
    await using server = new HttpServer({});
    await server.listen();

    const res = await fetch(`${server.url}/missing`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(404);
  });

  it("returns 405 for a non-POST request", async () => {
    await using server = new HttpServer({
      "/hello": async (_req, res) => { res.writeHead(200); res.end(); },
    });
    await server.listen();

    const res = await fetch(`${server.url}/hello`, { method: "GET" });

    expect(res.status).toBe(405);
  });

  it("returns 500 when the handler throws", async () => {
    await using server = new HttpServer({
      "/boom": () => {
        throw new Error("oops");
      },
    });
    await server.listen();

    const res = await fetch(`${server.url}/boom`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(500);
  });

  it("forwards a non-200 status from the handler", async () => {
    await using server = new HttpServer({
      "/fail": async (_req, res) => {
        res.writeHead(403);
        res.end('{ "error": "nope" }');
      },
    });
    await server.listen();

    const res = await fetch(`${server.url}/fail`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "nope" });
  });
});
