import { Card, CardContent } from "@/components/ui/card";
import { Meta, Title } from "react-head";
import { Sparkles } from "lucide-react";
import { useAuth } from "@/contexts/auth-context";
import { Navigate } from "react-router-dom";

export function HomePage() {
  const { isAuthenticated, clearTokens } = useAuth();

  if (!isAuthenticated) {
    clearTokens();
    return <Navigate to="/oauth-demo" />;
  }

  return (
    <>
      <Title>Home | Aetheris.Labs</Title>
      <Meta
        name="description"
        content="Bem-vindo à página inicial do Aetheris.Labs"
      />
      <Meta name="robots" content="noindex, nofollow" />

      <div className="flex flex-col items-center justify-center min-h-[80vh] px-4">
        <Card className="w-full max-w-xl p-0 rounded-2xl shadow-2xl border-none bg-[rgba(20,20,20,0.95)]">
          <CardContent className="pt-10 pb-10 px-8 flex flex-col items-center">
            <div className="size-16 bg-white/10 rounded-full flex items-center justify-center mb-6">
              <Sparkles className="size-8 text-white animate-pulse" />
            </div>
            <h1 className="text-3xl font-bold mb-2 text-white text-center">
              Bem-vindo ao{" "}
              <span className="text-indigo-400">Aetheris.Labs</span>
            </h1>
            <p className="text-white/70 text-lg text-center mb-6">
              Esta é a sua nova página inicial. Explore as funcionalidades e
              aproveite a experiência!
            </p>
            <a
              href="/oauth-demo"
              className="mt-2 px-6 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white font-semibold transition"
            >
              Ir para o Demo OAuth
            </a>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
