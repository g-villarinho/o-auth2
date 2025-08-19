import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ChromeIcon, AppleIcon } from "@/components/icons";
import { Lock } from "lucide-react";
import { SignInForm } from "./sign-in-form";
import { Meta, Title } from "react-head";

import { useQueryState } from "@/hooks/use-query-state";
import { Navigate } from "react-router-dom";

export function SignInPage() {
  const [continueUrl] = useQueryState("continue");

  if (!continueUrl) {
    return <Navigate to="/oauth-demo" />;
  }

  return (
    <>
      <Title>Sign in | Aetheris-Labs</Title>
      <Meta name="description" content="Sign in to your account to continue" />
      <Meta name="robots" content="noindex, nofollow" />

      <Card className="w-full p-0">
        <CardContent className="pt-8 pb-8 px-6">
          <div className="mb-6">
            <div className="size-12 bg-white/10 rounded-full flex items-center justify-center mb-4">
              <Lock className="size-6 text-white" />
            </div>
            <h2 className="text-2xl font-bold mb-2 text-white">Welcome back</h2>
            <p className="text-white/60 text-sm">
              Sign in to your account to continue
            </p>
          </div>
          <SignInForm continueUrl={continueUrl} />
          <div className="flex items-center my-6">
            <div className="flex-1 h-px bg-white/10" />
            <span className="mx-4 text-xs text-white/60">OR SIGN IN WITH</span>
            <div className="flex-1 h-px bg-white/10" />
          </div>
          <div className="flex gap-4">
            <Button
              variant="outline"
              size="lg"
              className="flex-1 flex items-center justify-center gap-2"
            >
              <ChromeIcon className="size-4" style={{ fill: "white" }} />
              Google
            </Button>
            <Button
              variant="outline"
              size="lg"
              className="flex-1 flex items-center justify-center gap-2"
            >
              <AppleIcon className="size-4" style={{ fill: "white" }} />
              Apple
            </Button>
          </div>
        </CardContent>
      </Card>
    </>
  );
}
