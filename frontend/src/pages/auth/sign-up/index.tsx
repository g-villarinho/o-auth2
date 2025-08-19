import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { UserPlus } from "lucide-react";
import { AppleIcon, ChromeIcon } from "@/components/icons";
import { SignUpForm } from "./sign-up-form";
import { useQueryState } from "@/hooks/use-query-state";
import { Meta, Title } from "react-head";
import { Navigate } from "react-router-dom";

export function SignUpPage() {
  const [continueUrl] = useQueryState("continue");

  if (!continueUrl) {
    return <Navigate to="/oauth-demo" />;
  }

  return (
    <>
      <Title>Create an account | Aetheris</Title>
      <Meta name="description" content="Create an account to continue" />
      <Meta name="robots" content="noindex, nofollow" />

      <Card className="w-full max-w-md p-0 rounded-2xl shadow-2xl border-none bg-[rgba(20,20,20,0.95)]">
        <CardContent className="pt-8 pb-8 px-6">
          <div className="mb-6">
            <div className="size-12 bg-white/10 rounded-full flex items-center justify-center mb-4">
              <UserPlus className="size-6 text-white" />
            </div>
            <h2 className="text-2xl font-bold mb-2 text-white">
              Create an account
            </h2>
            <p className="text-white/60 text-sm">
              Create an account to continue
            </p>
          </div>
          <SignUpForm continueUrl={continueUrl} />
          <div className="flex items-center my-6">
            <div className="flex-1 h-px bg-white/10" />
            <span className="mx-4 text-xs text-white/60">OR SIGN UP WITH</span>
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
          <p className="mt-6 text-xs text-center text-white/40">
            By creating an account, you agree to our{" "}
            <a href="#" className="underline">
              Terms & Service
            </a>
          </p>
        </CardContent>
      </Card>
    </>
  );
}
