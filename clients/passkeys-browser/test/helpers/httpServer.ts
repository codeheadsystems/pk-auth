// SPDX-License-Identifier: MIT
import * as http from "node:http";
import {ServerResponse} from "node:http";

/*
HttpServer is a server used for testing purposes.
Pass in a map of path to handler and any POST request on that path
will invoke the respective handler.
- listen() sets up the server to listen on a random port
- close() shuts the server down
- async dispose() to support async using similar to auto close in java
- url to return the url the server is listening on
A common usage is:
    await using server = new HttpServer({
      "/hello": async (req, res) => {
          w.writeHead(200, { "content-type"": "text/plain"" });
          w.end("howdy");
      },
    });
    await server.listen();
    console.log(server.url)
 */
export class HttpServer {
  private readonly server: http.Server;
  private _url = "";

  constructor(private readonly routes: Record<string, HttpHandler>) {
    this.server = http.createServer((req, res) => void this.handle(req, res));
  }

  listen(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen(0, "127.0.0.1", () => {
        this.server.off("error", reject);
        const addr = this.server.address() as { port: number };
        this._url = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  }

  close(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server.close((err) => (err ? reject(err) : resolve()));
    });
  }

  [Symbol.asyncDispose](): Promise<void> {
    return this.close();
  }

  [Symbol.dispose](): Promise<void> {
    return this.close();
  }

  get url(): string {
    if (!this._url) throw new Error("HttpServer: call listen() before accessing url");
    return this._url;
  }

  private async handle(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    const path = req.url ?? "";
    const handler = this.routes[path];

    if (!handler) {
      res.writeHead(404);
      res.end();
      return;
    }
    if (req.method !== "POST") {
      res.writeHead(405);
      res.end();
      return;
    }

    try {
      await handler(req, res);
    } catch(err) {
      errorHttp(err, res)
    }
  }
}

// Handler has three pieces: a decoder to decode http requests to a structured request,
// an endpoint to take a structured request and return a structured response,
// an encoder to take a structured response and encode it on the wire as an http response.
export class Handler<Req, Res> {
  constructor(
    readonly decoder: Decoder<Req>,
    readonly endpoint: Endpoint<Req, Res>,
    readonly encoder: Encoder<Res>,
  ) {}
}

// Decoder decodes an http request to a structured type.
export type Decoder<Req> = (msg: http.IncomingMessage) => Promise<Req> | Req;

// Encoder takes a structured type and writes it as an http response with headers and status code.
export type Encoder<Res> = (res: Res, w: http.ServerResponse) => Promise<void> | void;

// Endpoint is the business logic. It takes a structured request and returns a structured response.
// An endpoint is agnostic of the transport; it knows nothing about http requests and responses.
export type Endpoint<Req, Res> = (req: Req) => Promise<Res>;

// HttpHandler takes in an http request; and actions on the http response.
export type HttpHandler = (req: http.IncomingMessage, res: http.ServerResponse) => Promise<void> | void;

export class HttpError extends Error {
  constructor(readonly status: number, readonly body: unknown) {
    super(`HTTP ${status}`);
  }
}

export function newHttpHandler<Req, Res>(handler: Handler<Req, Res>): HttpHandler {
  return async (req, res) => {
    try {
      const request = await handler.decoder(req);
      const response = await handler.endpoint(request);
      await handler.encoder(response, res);
    } catch (err) {
      errorHttp(err, res)
    }
  };
}

export async function encodeJson<T>(res: T, w: http.ServerResponse): Promise<void> {
  w.writeHead(200, { [contentType]: applicationJson });
  w.end(JSON.stringify(res));
}

export async function decodeJson<T>(msg: http.IncomingMessage): Promise<T> {
  const chunks: Buffer[] = [];
  for await (const chunk of msg) chunks.push(chunk as Buffer);
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as T;
}

function errorHttp(err: any, res: ServerResponse) {
  const headers = { [contentType]: applicationJson }
  if (err instanceof HttpError) {
    res.writeHead(err.status, headers);
    res.end(JSON.stringify(err.body));
  } else if (err instanceof Error) {
    res.writeHead(500);
    res.end(err.message);
  } else {
    res.writeHead(500);
    res.end();
  }
}

const contentType = 'content-type';
const applicationJson = 'application/json';
