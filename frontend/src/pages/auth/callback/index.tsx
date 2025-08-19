import { useEffect, useState } from "react";
import { Meta, Title } from "react-head";
import { Card, CardContent } from "@/components/ui/card";
import { ShieldAlert, ShieldCheck } from "lucide-react";
import { env } from "@/env";
import { api } from "@/lib/axios";
import { useAuth } from "@/contexts/auth-context";

export function OauthCallbackPage() {
  const { setTokens } = useAuth();
  const [status, setStatus] = useState<
    "idle" | "loading" | "success" | "error"
  >("idle");
  const [errorMessage, setErrorMessage] = useState<string>("");

  useEffect(function effectExchangeCode() {
    async function exchangeAuthorizationCode() {
      setStatus("loading");

      const urlParams = new URLSearchParams(window.location.search);
      const code = urlParams.get("code");
      if (!code) {
        setErrorMessage("Código de autorização ausente na URL.");
        setStatus("error");
        return;
      }

      const codeVerifier = sessionStorage.getItem("pkce_code_verifier");
      if (!codeVerifier) {
        setErrorMessage("Code Verifier não encontrado (sessão expirada?).");
        setStatus("error");
        return;
      }

      const clientId = env.VITE_OAUTH_CLIENT_ID;
      const redirectUri = env.VITE_OAUTH_REDIRECT_URI;

      const body = new URLSearchParams();
      body.set("code", code);
      body.set("code_verifier", codeVerifier);
      body.set("client_id", clientId);
      body.set("redirect_uri", redirectUri);

      try {
        const response = await api.post("/oauth/token", body, {
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
        });

        const { access_token, refresh_token, id_token } = response.data;

        setTokens({
          accessToken: access_token,
          refreshToken: refresh_token,
          idToken: id_token,
        });

        setStatus("success");
        sessionStorage.removeItem("pkce_code_verifier");
        sessionStorage.removeItem("oauth_state");
        window.location.href = "/";
      } catch (error) {
        setErrorMessage("Falha ao trocar o código por token.");
        setStatus("error");
      }
    }

    exchangeAuthorizationCode();
  }, []);

  return (
    <>
      <Title>OAuth2 Callback</Title>
      <Meta name="robots" content="noindex, nofollow" />

      <Card className="w-full p-0">
        <CardContent className="pt-8 pb-8 px-6">
          {status === "loading" && (
            <div>
              <div className="size-12 bg-white/10 rounded-full flex items-center justify-center mb-4">
                <ShieldCheck className="size-6 text-white animate-pulse" />
              </div>
              <h2 className="text-2xl font-bold mb-2 text-white">
                Autenticando...
              </h2>
              <p className="text-white/60 text-sm">
                Trocando o código por token no servidor.
              </p>
            </div>
          )}

          {status === "success" && (
            <div>
              <div className="size-12 bg-white/10 rounded-full flex items-center justify-center mb-4">
                <ShieldCheck className="size-6 text-white" />
              </div>
              <h2 className="text-2xl font-bold mb-2 text-white">
                Autenticado com sucesso
              </h2>
              <p className="text-white/60 text-sm">
                Você já pode voltar para a aplicação.
              </p>
            </div>
          )}

          {status === "error" && (
            <div>
              <div className="size-12 bg-white/10 rounded-full flex items-center justify-center mb-4">
                <ShieldAlert className="size-6 text-white" />
              </div>
              <h2 className="text-2xl font-bold mb-2 text-white">Erro</h2>
              <p className="text-white/60 text-sm">{errorMessage}</p>
            </div>
          )}
        </CardContent>
      </Card>
    </>
  );
}
