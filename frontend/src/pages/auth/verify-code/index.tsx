import { Meta, Title } from "react-head";
import { Card, CardContent } from "@/components/ui/card";
import { KeyRound } from "lucide-react";
import { VerifyCodeForm } from "./verify-code-form";
import { ResendCodeButton } from "./resend-code-button";
import { useQueryState } from "@/hooks/use-query-state";
import { Navigate } from "react-router-dom";

export function VerifyCodePage() {
  const [continueUrl] = useQueryState("continue");

  if (!continueUrl) {
    return <Navigate to="/oauth-demo" />;
  }

  return (
    <>
      <Title>Verify code | Aetheris.Labs</Title>
      <Meta name="description" content="Verify code to continue" />
      <Meta name="robots" content="noindex, nofollow" />

      <Card className="w-full p-0">
        <CardContent className="pt-8 pb-8 px-6">
          <div className="mb-6">
            <div className="size-12 bg-white/10 rounded-full flex items-center justify-center mb-4">
              <KeyRound className="size-6 text-white" />
            </div>
            <h2 className="text-2xl font-bold mb-2 text-white">Verify code</h2>
            <p className="text-white/60 text-sm">
              Verify the code sent to your email
            </p>
          </div>
          <VerifyCodeForm continueUrl={continueUrl} />
          <ResendCodeButton className="mt-4" />
        </CardContent>
      </Card>
    </>
  );
}
