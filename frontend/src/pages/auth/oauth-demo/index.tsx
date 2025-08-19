import { Meta, Title } from "react-head";
import { Card, CardContent } from "@/components/ui/card";
import { ShieldCheck } from "lucide-react";
import { useOAuth } from "@/hooks/use-oauth";
import { useTransition } from "react";
import { SubmissionButton } from "@/components/submission-button";

export function OauthDemoPage() {
  const { generateAuthUrl } = useOAuth();
  const [isPending, startTransition] = useTransition();

  async function handleAuthorizeClick() {
    startTransition(async () => {
      const authUrl = await generateAuthUrl();
      window.location.replace(authUrl);
    });
  }

  return (
    <>
      <Title>OAuth2 Demo | Authorize</Title>
      <Meta name="description" content="Demo de autorização OAuth2 com PKCE" />
      <Meta name="robots" content="noindex, nofollow" />

      <Card className="w-full p-0">
        <CardContent className="pt-8 pb-8 px-6">
          <div className="mb-6">
            <div className="size-12 bg-white/10 rounded-full flex items-center justify-center mb-4">
              <ShieldCheck className="size-6 text-white" />
            </div>
            <h2 className="text-2xl font-bold mb-2 text-white">OAuth2 Demo</h2>
            <p className="text-white/60 text-sm">
              Clique em Logar para iniciar o fluxo de autorização com PKCE
            </p>
          </div>
          <SubmissionButton
            className="w-full"
            loading={isPending}
            onClick={handleAuthorizeClick}
          >
            Logar
          </SubmissionButton>
        </CardContent>
      </Card>
    </>
  );
}
