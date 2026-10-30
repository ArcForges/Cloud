// SPDX-License-Identifier: AGPL-3.0-only
// The functions of account.js that the repository's tests call (tests/worker/account-script.test.ts). The script is an ES module that
// runs in the browser; this file only gives its exports a type for the Node-side test project. It is not part of the image.

export interface ApiResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}

export interface Api {
  bootstrap(): Promise<{ csrfToken: string; authenticated: boolean }>;
  useToken(token: string): void;
  post(path: string, body?: unknown): Promise<unknown>;
}

export class ApiError extends Error {
  constructor(status: number, code: string);
  status: number;
  code: string;
}

export function errorText(error: unknown): string;
export function encodeBase64Url(input: ArrayBuffer | Uint8Array): string;
export function decodeBase64Url(text: string): Uint8Array;
export function safeReturnPath(value: unknown, origin: string): string | null;
export function parseFragment(hash: string): Record<string, string>;
export function requestOptions(challenge: unknown): Record<string, unknown>;
export function creationOptions(challenge: unknown, accountName: string): Record<string, unknown>;
export function assertionBody(credential: unknown): Record<string, unknown>;
export function creationBody(credential: unknown): Record<string, unknown>;
export function installationClaim(
  storage: unknown,
  random: { randomUUID(): string },
): { installationId: string; product: string; platform: string; appVersion: string };
export function createApi(
  base: string,
  fetchImpl: (url: string, init: RequestInit) => Promise<ApiResponse>,
): Api;
export function signIn(options: {
  api: Api;
  credentials: unknown;
  claim: unknown;
}): Promise<unknown>;
export function enroll(options: {
  api: Api;
  credentials: unknown;
  claim: unknown;
  token: string;
  displayName: string;
}): Promise<unknown>;
export function stepUp(options: {
  api: Api;
  credentials: unknown;
  operationClass: string;
  targetHash: string;
}): Promise<unknown>;
export function signOut(options: { api: Api }): Promise<unknown>;
export function start(window: unknown): Promise<unknown> | undefined;
