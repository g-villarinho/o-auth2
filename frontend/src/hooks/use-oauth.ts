import { env } from "@/env";


function base64UrlEncodeFromBytes(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function computeSha256Base64Url(input: string) {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return base64UrlEncodeFromBytes(new Uint8Array(digest));
}

function generateRandomState() {
  const randomBytes = crypto.getRandomValues(new Uint8Array(16));
  return base64UrlEncodeFromBytes(randomBytes);
}

function generateCodeVerifier() {
  const randomBytes = crypto.getRandomValues(new Uint8Array(64));
  return base64UrlEncodeFromBytes(randomBytes);
}

export function useOAuth() {
  async function generateAuthorizeUrl() {
    const clientId = env.VITE_OAUTH_CLIENT_ID;
    const redirectUri = env.VITE_OAUTH_REDIRECT_URI;
    const responseType = env.VITE_OAUTH_RESPONSE_TYPE;
    const scope = env.VITE_OAUTH_SCOPE;
    const endpoint = env.VITE_OAUTH_AUTORIZE_ENDPOINT;

    const state = generateRandomState();
    sessionStorage.setItem("oauth_state", state);

    const codeVerifier = generateCodeVerifier();
    sessionStorage.setItem("pkce_code_verifier", codeVerifier);

    const codeChallenge = await computeSha256Base64Url(codeVerifier);
    const codeChallengeMethod = "S256";

    const authorizeUrl = new URL(endpoint);
    authorizeUrl.searchParams.set("client_id", clientId);
    authorizeUrl.searchParams.set("redirect_uri", redirectUri);
    authorizeUrl.searchParams.set("response_type", responseType);
    authorizeUrl.searchParams.set("scope", scope);
    authorizeUrl.searchParams.set("state", state);
    authorizeUrl.searchParams.set("code_challenge", codeChallenge);
    authorizeUrl.searchParams.set("code_challenge_method", codeChallengeMethod);

    return authorizeUrl.toString();
  }

  return {
    generateAuthUrl: generateAuthorizeUrl,
  };
}