import { api } from "@/lib/axios";
import { useMutation } from "@tanstack/react-query";

export interface ExchangeTokenResponse {
  access_token: string;
  refresh_token: string;
  id_token: string;
}

export interface ExchangeTokenRequest {
  code: string;
  code_verifier: string;
  client_id: string;
  redirect_uri: string;
}

export function useExchangeToken() {
  return useMutation({
    mutationFn: async ({ code, code_verifier, client_id, redirect_uri }: ExchangeTokenRequest) => {
      const body = new URLSearchParams();
      body.set("code", code);
      body.set("code_verifier", code_verifier);
      body.set("client_id", client_id);
      body.set("redirect_uri", redirect_uri);

      const response = await api.post("/oauth/token", body, {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      });
      return response.data;
    },
  });
}