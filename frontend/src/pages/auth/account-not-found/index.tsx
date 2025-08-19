import { Card, CardContent } from "@/components/ui/card";
import { UserX } from "lucide-react";
import { Meta, Title } from "react-head";
import { useQueryState } from "@/hooks/use-query-state";
import { AccountNotFoundForm } from "./account-not-found-form";
import { Navigate } from "react-router-dom";

export function AccountNotFoundPage() {
  const [continueUrl] = useQueryState("continue");
  const [email] = useQueryState("email");

  if (!continueUrl) {
    return <Navigate to="/oauth-demo" />;
  }

  if (!email) {
    return <Navigate to={`/sign-in?continue=${continueUrl}`} replace />;
  }

  return (
    <>
      <Title>Account not found | Aetheris.Labs</Title>
      <Meta
        name="description"
        content="No account was found with this email address"
      />
      <Meta name="robots" content="noindex, nofollow" />

      <Card className="w-full p-0">
        <CardContent className="pt-8 pb-8 px-6">
          <div className="mb-6">
            <div className="size-12 bg-white/10 rounded-full flex items-center justify-center mb-4">
              <UserX className="size-6 text-white" />
            </div>
            <h2 className="text-2xl font-bold mb-2 text-white">
              Account not found for {email}
            </h2>
            <p className="text-white/60 text-sm">
              No account was found with this email address. Please try again or
              create a new account.
            </p>
          </div>
          <AccountNotFoundForm continueUrl={continueUrl} />
        </CardContent>
      </Card>
    </>
  );
}
