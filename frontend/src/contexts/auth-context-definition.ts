import { createContext } from "react";

interface Tokens {
  accessToken: string | null;
  refreshToken: string | null;
  idToken: string | null;
}

interface AuthContextType {
  tokens: Tokens;
  isAuthenticated: boolean;
  setTokens: (tokens: Tokens) => void;
  clearTokens: () => void;
}

export const AuthContext = createContext<AuthContextType | null>(null);
