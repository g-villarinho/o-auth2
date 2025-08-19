import { type ReactNode, useState } from "react";
import { AuthContext } from "./auth-context-definition";

interface Tokens {
  accessToken: string | null;
  refreshToken: string | null;
  idToken: string | null;
}

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [tokens, setTokensState] = useState<Tokens>(() => {
    const storedTokens = localStorage.getItem("aetheris-id");
    if (storedTokens) {
      return JSON.parse(storedTokens);
    }
    return {
      accessToken: null,
      refreshToken: null,
      idToken: null,
    };
  });

  const isAuthenticated = !!tokens.accessToken;

  function setTokens(newTokens: Tokens) {
    setTokensState(newTokens);

    localStorage.setItem(
      "aetheris-id",
      JSON.stringify({
        accessToken: newTokens.accessToken,
        refreshToken: newTokens.refreshToken,
        idToken: newTokens.idToken,
      })
    );
  }

  function clearTokens() {
    setTokensState({
      accessToken: null,
      refreshToken: null,
      idToken: null,
    });

    localStorage.removeItem("aetheris-id");
  }

  return (
    <AuthContext.Provider
      value={{
        tokens,
        isAuthenticated,
        setTokens,
        clearTokens,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
